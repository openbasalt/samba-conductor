// Package web is conductor's HTTP interface: server-rendered pages (no
// JavaScript at all), sessions bound to the user's own Kerberos ticket,
// per-route role checks re-validated against AD, previews before every
// write, and the audit log.
package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor/internal/config"
	"github.com/samba-conductor/conductor/internal/directory"
	"github.com/samba-conductor/conductor/internal/i18n"
	"github.com/samba-conductor/conductor/internal/ratelimit"
	"github.com/samba-conductor/conductor/internal/secret"
	"github.com/samba-conductor/conductor/internal/store"
)

// Backend is the directory as conductor uses it (directory.Directory in
// production, a fake in tests).
type Backend interface {
	Realm() string
	SignIn(ctx context.Context, username, password string) (*directory.Credential, error)
	Connect(ctx context.Context, c *directory.Credential) (*ad.Conn, error)
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
	MFABox  *secret.Box
	Helper  HelperClient // nil when the helper is disabled
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
		cat: cat, version: d.Version, now: time.Now}
	for _, p := range d.Config.Server.TrustedProxies {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		s.trusted = append(s.trusted, pre)
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
	if s.tmpl, err = s.loadTemplates(); err != nil {
		return nil, err
	}
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
