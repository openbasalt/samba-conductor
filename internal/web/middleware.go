package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor/internal/i18n"
)

// route is one entry of the route table: every handler is reachable only
// through it, so the guard below runs for every request.
type route struct {
	method  string
	pattern string
	perm    Perm
	// stages allowed for PermPreAuth routes.
	stages []stage
	h      func(*reqCtx)
	// script allows the self-hosted WebAuthn script on this page (CSP
	// nonce). Only second-factor pages set it; every other page stays
	// script-free (script-src 'none').
	script bool
	// maxBody overrides the request body limit (CSV uploads).
	maxBody int64
}

// reqCtx carries one request through a handler.
type reqCtx struct {
	s     *Server
	w     http.ResponseWriter
	r     *http.Request
	sess  *Session
	roles Roles
	lang  string
	theme string
	ip    string
	route route
	// actorHint names the actor of anonymous audit events (typed username).
	actorHint string
	// nonce of the page's script (script routes only).
	nonce string
}

func (rc *reqCtx) ctx() context.Context { return rc.r.Context() }

// T translates in the request's language.
func (rc *reqCtx) T(key string, args ...any) string { return rc.s.cat.T(rc.lang, key, args...) }

// maxBody bounds request bodies (forms are small).
const maxBody = 64 << 10

// cspPolicy: no script at all, styles and images only from this origin.
const cspPolicy = "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// cspWithScript is the policy of the second-factor pages: the same, except
// that the one script carrying this response's nonce may run. The script
// makes no requests of its own (connect-src stays 'none'): it fills a form
// field and submits the form.
func cspWithScript(nonce string) string {
	return strings.Replace(cspPolicy, "script-src 'none'", "script-src 'nonce-"+nonce+"'", 1)
}

// withMediaOrigins adds allowlisted https origins (validated by the
// configuration) to img-src and font-src of a policy; nothing else
// changes.
func withMediaOrigins(policy string, origins []string) string {
	extra := ""
	for _, o := range origins {
		if strings.HasPrefix(o, "https://") && !strings.ContainsAny(o, " ;,'\"") {
			extra += " " + o
		}
	}
	policy = strings.Replace(policy, "img-src 'self'", "img-src 'self'"+extra, 1)
	return strings.Replace(policy, "font-src 'self'", "font-src 'self'"+extra, 1)
}

func (s *Server) securityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", cspPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	// Conductor is only ever served over HTTPS (directly or via a proxy).
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
}

// clientIP returns the peer address, or the X-Forwarded-For entry added by
// a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !s.cfg.Server.BehindProxy || !s.isTrusted(peer) {
		return peer.String()
	}
	// Walk X-Forwarded-For from the right, skipping trusted proxies.
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

func (s *Server) isTrusted(a netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// wrap applies the common pipeline and the route's guard.
func (s *Server) wrap(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.securityHeaders(w.Header())
		w.Header().Set("Cache-Control", "no-store")
		limit := int64(maxBody)
		if rt.maxBody > 0 {
			limit = rt.maxBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		rc := &reqCtx{s: s, w: w, r: r, route: rt, ip: s.clientIP(r)}
		if rt.script && r.Method == http.MethodGet {
			rc.nonce = newToken()[:24]
			w.Header().Set("Content-Security-Policy", cspWithScript(rc.nonce))
		}
		s.prefs(rc)
		if c, err := r.Cookie(sessionCookie); err == nil {
			rc.sess = s.sess.get(r.Context(), c.Value)
		}
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("handler panic", "path", r.URL.Path, "panic", v)
				rc.errorPage(http.StatusInternalServerError, "err.internal")
			}
		}()
		if r.Method == http.MethodPost && !s.checkCSRF(rc) {
			s.audit(r.Context(), rc, "security.csrf_rejected", r.URL.Path, "", "denied")
			rc.errorPage(http.StatusForbidden, "err.csrf")
			return
		}
		if !s.guard(rc) {
			return
		}
		rt.h(rc)
	})
}

// prefs resolves language and theme; ?lang= and ?theme= on a GET store the
// choice in a cookie (UI preferences only, no security relevance).
func (s *Server) prefs(rc *reqCtx) {
	r := rc.r
	langCookie, themeCookie := "", ""
	if c, err := r.Cookie("lang"); err == nil {
		langCookie = c.Value
	}
	if c, err := r.Cookie("theme"); err == nil {
		themeCookie = c.Value
	}
	if r.Method == http.MethodGet {
		if l := r.URL.Query().Get("lang"); i18n.Valid(l) {
			langCookie = l
			http.SetCookie(rc.w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 365 * 24 * 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
		if t := r.URL.Query().Get("theme"); slices.Contains([]string{"light", "dark", "system"}, t) {
			themeCookie = t
			http.SetCookie(rc.w, &http.Cookie{Name: "theme", Value: t, Path: "/", MaxAge: 365 * 24 * 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
	}
	rc.lang = i18n.Negotiate(r, langCookie, s.cfg.UI.DefaultLanguage)
	if themeCookie == "light" || themeCookie == "dark" {
		rc.theme = themeCookie
	}
}

// checkCSRF verifies a state-changing request: same-origin by Fetch
// metadata / Origin, and the token of the session (or, for the sign-in
// form, the pre-session cookie: double submit).
func (s *Server) checkCSRF(rc *reqCtx) bool {
	r := rc.r
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		// Uploads (CSV import) only on routes that raised the body limit;
		// parsed in memory (the limit bounds it), never to disk.
		if rc.route.maxBody == 0 || r.ParseMultipartForm(rc.route.maxBody) != nil {
			return false
		}
	} else if err := r.ParseForm(); err != nil {
		return false
	}
	tok := r.PostForm.Get("csrf")
	if rc.sess != nil {
		rc.sess.mu.Lock()
		want := rc.sess.csrf
		rc.sess.mu.Unlock()
		if tokensEqual(tok, want) {
			return true
		}
	}
	if rc.route.perm == PermPublic {
		// Sign-in form: no session yet, the token is bound to the
		// pre-session cookie.
		if c, err := r.Cookie(preCookie); err == nil && tokensEqual(tok, c.Value) {
			return true
		}
	}
	return false
}

// guard enforces the route's permission before the handler runs.
func (s *Server) guard(rc *reqCtx) bool {
	rt := rc.route
	switch rt.perm {
	case PermPublic:
		return true
	case PermPreAuth:
		if rc.sess == nil || !slices.Contains(rt.stages, rc.sess.snapshotStage()) {
			rc.redirectSignin("")
			return false
		}
		return true
	}
	if rc.sess == nil {
		rc.redirectSignin("")
		return false
	}
	switch st := rc.sess.snapshotStage(); st {
	case stageFull:
	case stageMFA:
		rc.redirect("/signin/2fa")
		return false
	case stageEnroll:
		rc.redirect("/signin/enroll")
		return false
	case stageMustChange:
		rc.redirect("/signin/password")
		return false
	default:
		rc.redirectSignin("")
		return false
	}
	if !rt.perm.privileged() {
		// Self-service still knows the roles for the navigation.
		rc.sess.mu.Lock()
		rc.roles = rc.sess.roles
		rc.sess.mu.Unlock()
		return true
	}
	roles, err := s.rolesFor(rc.ctx(), rc.sess)
	if err != nil {
		// The ticket expired or AD is unreachable: a privileged decision
		// cannot be made on stale data.
		s.log.Warn("role re-check failed", "user", rc.sess.sam, "err", err)
		s.sess.destroy(rc.ctx(), rc.sess)
		clearCookie(rc.w, sessionCookie)
		rc.redirectSignin("reauth")
		return false
	}
	rc.roles = roles
	if !roles.Has(rt.perm) {
		s.audit(rc.ctx(), rc, "access.denied", rc.r.Method+" "+rc.r.URL.Path, "requires "+string(rt.perm), "denied")
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return false
	}
	rc.sess.mu.Lock()
	verified, keyOK := rc.sess.mfaVerified, rc.sess.keyOK
	rc.sess.mu.Unlock()
	if (s.mfaRequired(roles) && !verified) || (s.keyRequired(roles) && !keyOK) {
		// The user gained a role that needs 2FA after signing in without
		// it: start over so the sign-in flow enforces it.
		s.audit(rc.ctx(), rc, "access.denied", rc.r.Method+" "+rc.r.URL.Path, "2FA required for this role", "denied")
		s.sess.destroy(rc.ctx(), rc.sess)
		clearCookie(rc.w, sessionCookie)
		rc.redirectSignin("mfa_required")
		return false
	}
	return true
}

func (rc *reqCtx) redirect(path string) {
	http.Redirect(rc.w, rc.r, path, http.StatusSeeOther)
}

// redirectSignin sends to the sign-in page with an allowlisted message.
func (rc *reqCtx) redirectSignin(msg string) {
	if msg == "" {
		rc.redirect("/signin")
		return
	}
	rc.redirect("/signin?m=" + url.QueryEscape(msg))
}

// requestTimeout bounds directory work per request.
const requestTimeout = 60 * time.Second
