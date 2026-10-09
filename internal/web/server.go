// Package web is conductor's HTTP interface: server-rendered pages (no
// JavaScript at all), sessions bound to the user's own Kerberos ticket,
// per-route role checks re-validated against AD, previews before every
// write, and the audit log.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/directory"
	"github.com/openbasalt/samba-conductor/internal/i18n"
	"github.com/openbasalt/samba-conductor/internal/ratelimit"
	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Backend is the directory as conductor uses it (directory.Directory in
// production, a fake in tests).
type Backend interface {
	Realm() string
	SignIn(ctx context.Context, username, password string) (*directory.Credential, error)
	Connect(ctx context.Context, c *directory.Credential) (*ad.Conn, error)
	// ConnectTo binds to one given DC (per-DC attributes).
	ConnectTo(ctx context.Context, c *directory.Credential, host string) (*ad.Conn, error)
	ChangeExpiredPassword(ctx context.Context, username, oldPassword, newPassword string) error
}

// HelperClient calls conductor-helper.
type HelperClient interface {
	Call(ctx context.Context, req helper.Request) (helper.Response, error)
}

// Deps are the server's collaborators.
type Deps struct {
	Config  *config.Config
	Store   *store.Store
	Backend Backend
	// MFABox seals TOTP secrets (key from systemd credentials).
	MFABox *secret.Box
	Helper HelperClient // nil when the helper is disabled
	// Sync is conductor-sync's management API (nil when [sync] is off).
	Sync SyncClient
	// Files reaches the conductor-files agents (nil when [files] is off).
	Files FilesClient
	// IDP is conductor-idp's management API (nil when [idp] is off).
	IDP     IDPClient
	Logger  *slog.Logger
	Version string
}

// Server serves the web interface.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	backend  Backend
	box      *secret.Box
	helper   HelperClient
	log      *slog.Logger
	cat      *i18n.Catalog
	version  string
	tmpl     map[string]map[string]*template.Template // lang → page → template
	sess     *sessions
	roleSIDs roleSIDs
	trusted  []netip.Prefix
	now      func() time.Time

	ipLimit      *ratelimit.Bucket
	accountFails *ratelimit.Failures
	mfaFails     *ratelimit.Failures

	// identify reads the signed-in user's entry and group SIDs with their
	// own credential. Replaced in tests.
	identify func(ctx context.Context, c *directory.Credential, sam string) (directory.Identity, []sid.SID, error)
	// groupsOf recomputes a session's group SIDs (role re-check).
	groupsOf func(ctx context.Context, s *Session) ([]sid.SID, error)

	mux    *http.ServeMux
	routes []route

	// wa is nil when WebAuthn is not configured.
	wa *webauthn.WebAuthn
	// scriptSRI is the Subresource Integrity hash of static/webauthn.js.
	scriptSRI string
	// jobs holds bulk jobs in memory; bgJobs tracks running ones.
	jobs   jobs
	bgJobs sync.WaitGroup

	// backups caches conductor-backup's status (dashboard banner);
	// backupPollErr is the poller's last error (logged on change only).
	backups       backupCache
	backupPollErr string

	// sync is conductor-sync's management API (nil when not enabled);
	// syncStatus caches its status for the dashboard card.
	sync       SyncClient
	syncStatus syncCache

	// files reaches the conductor-files agents (nil when not enabled);
	// filesStatus caches their status (list, dashboard).
	files       FilesClient
	filesStatus filesCache

	// idp is conductor-idp's management API (nil when [idp] is off).
	idp IDPClient
	// idpCeremonies are WebAuthn assertions started for conductor-idp
	// through the 2FA socket; mfaPeerCred replaces SO_PEERCRED in tests.
	idpCeremonies idpCeremonies
	mfaPeerCred   func(*net.UnixConn) (int, error)

	// brand is the current level 1 branding; tmplBuiltin are the pages
	// without template overrides (the fallback when one fails);
	// overridden lists the partials replaced by the template directory,
	// customCSS its custom.css; allowed are the origins branded pages may
	// load images and fonts from.
	brand       atomic.Pointer[brandState]
	tmplBuiltin map[string]map[string]*template.Template
	overridden  []string
	customCSS   []byte
	customTag   string
	allowed     []string
}

// New builds the server.
func New(d Deps) (*Server, error) {
	if d.Config == nil || d.Store == nil || d.Backend == nil || d.MFABox == nil {
		return nil, errors.New("web: missing dependency")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: d.Config, store: d.Store, backend: d.Backend, box: d.MFABox, helper: d.Helper, log: d.Logger,
		cat: cat, version: d.Version, now: time.Now, sync: d.Sync, files: d.Files, idp: d.IDP}
	for _, p := range d.Config.Server.TrustedProxies {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		s.trusted = append(s.trusted, pre)
	}
	if d.Config.Server.BehindProxy {
		// Say whose X-Forwarded-For is believed: rate limits and the audit
		// log use the client address it carries.
		d.Logger.Info("behind a reverse proxy", "trusted_proxies", strings.Join(d.Config.Server.TrustedProxies, ","))
	}
	if s.roleSIDs, err = parseRoleSIDs(d.Config.Roles); err != nil {
		return nil, err
	}
	rl := d.Config.RateLimit
	s.ipLimit = ratelimit.NewBucket(rl.PerIPPerMinute, time.Minute)
	window := time.Duration(rl.AccountWindowMinutes) * time.Minute
	s.accountFails = ratelimit.NewFailures(rl.AccountFailures, window)
	s.mfaFails = ratelimit.NewFailures(rl.AccountFailures, window)
	s.sess = &sessions{byID: map[string]*Session{}, store: d.Store, now: func() time.Time { return s.now() },
		idle: d.Config.IdleTimeout(), abs: d.Config.AbsoluteTimeout()}
	s.identify = s.identifyAD
	s.groupsOf = s.groupsOfAD
	if s.wa, err = newWebAuthn(d.Config); err != nil {
		return nil, fmt.Errorf("web: webauthn: %w", err)
	}
	js, err := staticFS.ReadFile("static/webauthn.js")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(js)
	s.scriptSRI = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	s.allowed = d.Config.AllowedOrigins()
	if s.tmplBuiltin, err = s.loadTemplates(nil); err != nil {
		return nil, err
	}
	s.tmpl = s.tmplBuiltin
	if d.Config.Branding.TemplatesDir != "" {
		res := s.loadOverrides()
		s.overridden, s.customCSS = res.Overridden, res.CustomCSS
		if s.customCSS != nil {
			s.customTag = tag(s.customCSS)
		}
		if len(s.overridden) > 0 {
			if s.tmpl, err = s.loadTemplates(res.Bodies); err != nil {
				return nil, err
			}
		}
	}
	lctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.loadBranding(lctx)
	cancel()
	s.routes = s.routeTable()
	s.buildMux()
	return s, nil
}

// buildMux registers every route of s.routes behind its guard.
func (s *Server) buildMux() {
	s.mux = http.NewServeMux()
	for _, rt := range s.routes {
		s.mux.Handle(rt.method+" "+rt.pattern, s.wrap(rt))
	}
	s.mux.Handle("GET /static/", s.staticHandler())
	s.brandRoutes()
	s.mux.Handle("/", s.wrap(route{method: "", pattern: "/", perm: PermPublic, h: s.notFound}))
}

func parseRoleSIDs(r config.Roles) (roleSIDs, error) {
	var out roleSIDs
	for _, set := range []struct {
		in  []string
		out *[]sid.SID
	}{{r.AdminGroups, &out.admin}, {r.HelpdeskGroups, &out.helpdesk}, {r.AuditorGroups, &out.auditor}} {
		for _, v := range set.in {
			s, err := sid.Parse(v)
			if err != nil {
				return out, fmt.Errorf("web: role group %q: %w", v, err)
			}
			*set.out = append(*set.out, s)
		}
	}
	return out, nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Start clears session rows left by a previous process (their tickets are
// gone) and starts the background sweeper until ctx ends.
func (s *Server) Start(ctx context.Context) error {
	if err := s.store.DeleteAllSessions(ctx); err != nil {
		return err
	}
	// Bulk jobs that were running when the previous process stopped:
	// their unattempted rows stay "pending" in the report.
	if n, err := s.store.InterruptBulkJobs(ctx); err != nil {
		return err
	} else if n > 0 {
		s.log.Warn("bulk jobs interrupted by a restart", "jobs", n)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sess.sweep(context.Background())
			}
		}
	}()
	if s.helper != nil {
		// Backup status for the dashboard banner, and backup/drill results
		// into conductor's state and audit log.
		go func() {
			s.pollBackups(ctx)
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.pollBackups(ctx)
				}
			}
		}()
	}
	return nil
}

// identifyAD connects as the user and reads who they are and their groups.
func (s *Server) identifyAD(ctx context.Context, c *directory.Credential, sam string) (directory.Identity, []sid.SID, error) {
	conn, err := s.backend.Connect(ctx, c)
	if err != nil {
		return directory.Identity{}, nil, err
	}
	defer func() { _ = conn.Close() }()
	id, err := directory.Whoami(ctx, conn, sam)
	if err != nil {
		return id, nil, err
	}
	groups, err := directory.GroupSIDs(ctx, conn, id.DN)
	return id, groups, err
}

func (s *Server) groupsOfAD(ctx context.Context, sess *Session) ([]sid.SID, error) {
	sess.mu.Lock()
	cred, dn := sess.cred, sess.dn
	sess.mu.Unlock()
	if cred == nil {
		return nil, directory.ErrCredentialClosed
	}
	conn, err := s.backend.Connect(ctx, cred)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return directory.GroupSIDs(ctx, conn, dn)
}

// rolesFor returns the session's roles, re-checked against AD when the
// cached answer is older than the configured TTL (at most 60 s).
func (s *Server) rolesFor(ctx context.Context, sess *Session) (Roles, error) {
	sess.mu.Lock()
	fresh := !sess.rolesAt.IsZero() && s.now().Sub(sess.rolesAt) < s.cfg.RoleCacheTTL()
	roles := sess.roles
	sess.mu.Unlock()
	if fresh {
		return roles, nil
	}
	groups, err := s.groupsOf(ctx, sess)
	if err != nil {
		return Roles{}, err
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.groupSIDs = groups
	sess.roles = s.roleSIDs.resolve(sess.userSID, groups)
	sess.rolesAt = s.now()
	return sess.roles, nil
}

// mfaRequired reports whether a user with these roles must use 2FA.
func (s *Server) mfaRequired(r Roles) bool {
	if r.Admin {
		return true
	}
	if (r.Helpdesk || r.Auditor) && s.cfg.DelegatedMFARequired() {
		return true
	}
	return s.cfg.MFA.Policy == config.MFARequired
}

// audit appends an event; failures are logged (the action already
// happened) but never shown to the user.
func (s *Server) audit(ctx context.Context, rc *reqCtx, action, target, detail, result string) {
	e := store.AuditEvent{Action: action, Target: target, Detail: detail, Result: result}
	if rc != nil {
		e.IP, e.UserAgent = rc.ip, rc.r.UserAgent()
		if rc.sess != nil {
			rc.sess.mu.Lock()
			e.ActorSID, e.ActorName = rc.sess.userSID.String(), rc.sess.sam
			rc.sess.mu.Unlock()
		}
		if e.ActorName == "" {
			e.ActorName = rc.actorHint
		}
	}
	if _, err := s.store.AppendAudit(ctx, e); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}
