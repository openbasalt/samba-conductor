// Package directory adapts the ad library to conductor: sign-in with the
// user's own credentials (Kerberos first, simple bind only when configured),
// connections bound as the signed-in user, and the lookups conductor needs
// for roles.
package directory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/secret"
)

// Directory reaches the domain.
type Directory struct {
	cfg      ad.Config
	fallback bool
	box      *secret.Box // per-process key for simple-bind passwords
}

// New builds a Directory from the configuration.
func New(c *config.Config) (*Directory, error) {
	pemData, err := os.ReadFile(c.Domain.CAFile)
	if err != nil {
		return nil, fmt.Errorf("directory: reading the domain CA: %w", err)
	}
	pool, err := ad.CertPoolFromPEM(pemData)
	if err != nil {
		return nil, err
	}
	cfg := ad.Config{Realm: strings.ToUpper(c.Domain.Realm), DCs: c.Domain.DCs, Preferred: c.Domain.Preferred, RootCAs: pool}
	if len(c.Domain.DNSServers) > 0 {
		cfg.Resolver = ad.NewDNSResolver(c.Domain.DNSServers...)
	}
	box, err := secret.NewRandom()
	if err != nil {
		return nil, err
	}
	return &Directory{cfg: cfg, fallback: c.Domain.SimpleBindFallback, box: box}, nil
}

// Realm returns the Kerberos realm.
func (d *Directory) Realm() string { return d.cfg.Realm }

// Credential is a signed-in identity held for a session, in memory only:
// a Kerberos TGT, or (fallback) the password sealed with a per-process key.
type Credential struct {
	mu       sync.Mutex
	krb      *ad.Session
	username string
	sealed   []byte
	box      *secret.Box
	closed   bool
}

// Mechanism is "kerberos" or "simple".
func (c *Credential) Mechanism() string {
	if c.krb != nil {
		return "kerberos"
	}
	return "simple"
}

// Close forgets the ticket or password.
func (c *Credential) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.krb != nil {
		c.krb.Close()
	}
	clear(c.sealed)
	c.sealed = nil
}

// NormalizeUsername turns "LAB\\user", "user@realm" or "user" into the
// sAMAccountName part, lower-cased for rate limiting and lookups. ok is
// false for input that cannot be an account name.
func NormalizeUsername(input, realm string) (string, bool) {
	u := strings.TrimSpace(input)
	if _, after, ok := strings.Cut(u, "\\"); ok {
		u = after
	}
	if before, after, ok := strings.Cut(u, "@"); ok {
		if !strings.EqualFold(after, realm) {
			return "", false
		}
		u = before
	}
	if u == "" || len(u) > 64 || strings.ContainsAny(u, "\"/\\[]:;|=,+*?<>@") || strings.ContainsFunc(u, func(r rune) bool { return r < 0x20 }) {
		return "", false
	}
	return strings.ToLower(u), true
}

// SignIn verifies username and password with the KDC and returns the
// credential to keep for the session. Refusals are *ad.AuthError. With the
// fallback enabled and no KDC reachable, an LDAP simple bind decides.
func (d *Directory) SignIn(ctx context.Context, username, password string) (*Credential, error) {
	s, err := ad.SignIn(ctx, d.cfg, username, password)
	if err == nil {
		return &Credential{krb: s, username: username}, nil
	}
	var ae *ad.AuthError
	if errors.As(err, &ae) || !d.fallback {
		return nil, err
	}
	// The KDC was unreachable: try the explicit simple-bind fallback.
	conn, berr := ad.Connect(ctx, d.cfg, ad.SimpleAuth(username, password))
	if berr != nil {
		return nil, berr
	}
	_ = conn.Close()
	sealed, serr := d.box.Seal([]byte(password), []byte(strings.ToLower(username)))
	if serr != nil {
		return nil, serr
	}
	return &Credential{username: username, sealed: sealed, box: d.box}, nil
}

// ErrCredentialClosed is returned for a signed-out credential.
var ErrCredentialClosed = errors.New("directory: credential closed")

// Connect opens an LDAPS connection bound as the credential's user.
func (d *Directory) Connect(ctx context.Context, c *Credential) (*ad.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrCredentialClosed
	}
	if c.krb != nil {
		krb := c.krb
		c.mu.Unlock()
		return ad.Connect(ctx, d.cfg, ad.KerberosAuth(krb))
	}
	pw, err := c.box.Open(c.sealed, []byte(strings.ToLower(c.username)))
	username := c.username
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	return ad.Connect(ctx, d.cfg, ad.SimpleAuth(username, string(pw)))
}

// ConnectTo opens a connection bound as the credential's user to one given
// DC (per-DC attributes such as badPwdCount are not replicated).
func (d *Directory) ConnectTo(ctx context.Context, c *Credential, host string) (*ad.Conn, error) {
	one := d.cfg
	one.DCs = []string{host}
	one.Preferred = nil
	dd := &Directory{cfg: one, fallback: d.fallback, box: d.box}
	return dd.Connect(ctx, c)
}

// ErrNoTicket is returned when a tool needs a Kerberos ticket but the user
// signed in with the simple-bind fallback.
var ErrNoTicket = errors.New("directory: this action needs a Kerberos sign-in")

// WriteCCache writes the user's TGT to path (new file, 0600) for a tool
// that authenticates with a credential cache (samba-tool). The caller
// removes the file right after use.
func (c *Credential) WriteCCache(path string) error {
	c.mu.Lock()
	krb, closed := c.krb, c.closed
	c.mu.Unlock()
	if closed {
		return ErrCredentialClosed
	}
	if krb == nil {
		return ErrNoTicket
	}
	return krb.WriteCCache(path)
}

// ChangeExpiredPassword changes a password with the old one through
// kpasswd: it works for accounts that must change or whose password expired
// (they cannot bind to LDAP).
func (d *Directory) ChangeExpiredPassword(ctx context.Context, username, oldPassword, newPassword string) error {
	return ad.ChangePasswordKerberos(ctx, d.cfg, username, oldPassword, newPassword)
}

// Identity is what conductor keeps about the signed-in user.
type Identity struct {
	DN          string
	SID         sid.SID
	SAM         string
	DisplayName string
	UPN         string
}

// Whoami reads the signed-in user's own entry.
func Whoami(ctx context.Context, conn *ad.Conn, sam string) (Identity, error) {
	u, err := conn.FindUser(ctx, sam)
	if err != nil {
		return Identity{}, err
	}
	name := u.DisplayName
	if name == "" {
		name = u.SAMAccountName
	}
	return Identity{DN: u.DN, SID: u.SID, SAM: u.SAMAccountName, DisplayName: name, UPN: u.UserPrincipalName}, nil
}

// GroupSIDs returns the SIDs of every group dn belongs to, transitively and
// including the primary group: tokenGroups computed by the DC, with a
// fallback to an in-chain membership search when tokenGroups cannot be read.
func GroupSIDs(ctx context.Context, conn *ad.Conn, dn string) ([]sid.SID, error) {
	sids, err := conn.TokenGroups(ctx, dn)
	if err == nil && len(sids) > 0 {
		return sids, nil
	}
	var out []sid.SID
	for e, serr := range conn.Search(ctx, ad.SearchRequest{
		Filter:     escape.And(escape.Eq("objectClass", "group"), escape.InChain("member", dn)),
		Attributes: []string{"objectSid"},
	}) {
		if serr != nil {
			return nil, serr
		}
		if s, perr := sid.FromBytes(e.GetRawAttributeValue("objectSid")); perr == nil {
			out = append(out, s)
		}
	}
	// The primary group is not a "member" link.
	e, gerr := conn.Get(ctx, dn, "primaryGroupID", "objectSid")
	if gerr == nil {
		if us, perr := sid.FromBytes(e.GetRawAttributeValue("objectSid")); perr == nil {
			if dom, ok := us.Domain(); ok {
				var rid uint32
				_, _ = fmt.Sscan(e.GetAttributeValue("primaryGroupID"), &rid)
				if rid != 0 {
					if pg, werr := dom.WithRID(rid); werr == nil {
						out = append(out, pg)
					}
				}
			}
		}
	}
	return out, nil
}

// Expires returns when the credential stops working (the TGT end time); the
// zero time for the simple-bind fallback.
func (c *Credential) Expires() time.Time {
	if c.krb != nil {
		return c.krb.Expires()
	}
	return time.Time{}
}
