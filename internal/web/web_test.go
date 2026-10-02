package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor/internal/config"
	"github.com/samba-conductor/conductor/internal/directory"
	"github.com/samba-conductor/conductor/internal/secret"
	"github.com/samba-conductor/conductor/internal/store"
)

const (
	testDomain   = "S-1-5-21-1-2-3"
	helpdeskSID  = testDomain + "-2001"
	auditorSID   = testDomain + "-2002"
	domainAdmins = testDomain + "-512"
	testHost     = "conductor.test"
)

// fakeBackend answers sign-ins from a table.
type fakeBackend struct {
	mu      sync.Mutex
	calls   int
	results map[string]error // username → error (nil = success)
	changed map[string]bool
}

func (f *fakeBackend) Realm() string { return "LAB.TEST" }

func (f *fakeBackend) SignIn(_ context.Context, username, _ string) (*directory.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if err, ok := f.results[username]; ok && err != nil {
		return nil, err
	}
	if _, ok := f.results[username]; !ok {
		return nil, &ad.AuthError{Reason: ad.ReasonInvalidCredentials, Mechanism: "kerberos", Code: "KDC_ERR_C_PRINCIPAL_UNKNOWN"}
	}
	return &directory.Credential{}, nil
}

func (f *fakeBackend) Connect(context.Context, *directory.Credential) (*ad.Conn, error) {
	return nil, errors.New("fake backend: no LDAP")
}

func (f *fakeBackend) ChangeExpiredPassword(_ context.Context, username, oldPw, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if oldPw != "right" {
		return &ad.AuthError{Reason: ad.ReasonInvalidCredentials, Mechanism: "kerberos"}
	}
	if f.changed == nil {
		f.changed = map[string]bool{}
	}
	f.changed[username] = true
	return nil
}

// identities of the fake directory: username → groups.
var fakeUsers = map[string][]string{
	"normal.user":   {testDomain + "-513"},
	"helpdesk.user": {testDomain + "-513", helpdeskSID},
	"auditor.user":  {testDomain + "-513", auditorSID},
	"lab.admin":     {testDomain + "-513", domainAdmins},
}

var userRIDs = map[string]uint32{"normal.user": 1101, "helpdesk.user": 1102, "auditor.user": 1103, "lab.admin": 1104}

type harness struct {
	s       *Server
	backend *fakeBackend
	st      *store.Store
	now     time.Time
	// groups returned by the role re-check, per user SID.
	groups map[string][]sid.SID
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.Domain.Realm = "LAB.TEST"
	cfg.Domain.CAFile = "/dev/null"
	cfg.Server.TLSCert, cfg.Server.TLSKey = "/x/cert.pem", "/x/key.pem"
	cfg.Roles.HelpdeskGroups = []string{helpdeskSID}
	cfg.Roles.AuditorGroups = []string{auditorSID}
	cfg.RateLimit.PerIPPerMinute = 1000
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secret.NewRandom()
	fb := &fakeBackend{results: map[string]error{}}
	for u := range fakeUsers {
		fb.results[u] = nil
	}
	s, err := New(Deps{Config: cfg, Store: st, Backend: fb, MFABox: box, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{s: s, backend: fb, st: st, now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), groups: map[string][]sid.SID{}}
	s.now = func() time.Time { return h.now }
	st.SetClock(func() time.Time { return h.now })
	s.identify = func(_ context.Context, _ *directory.Credential, sam string) (directory.Identity, []sid.SID, error) {
		groups, ok := fakeUsers[sam]
		if !ok {
			return directory.Identity{}, nil, ad.ErrNotFound
		}
		us := sid.MustParse(testDomain).String()
		u, _ := sid.MustParse(us).WithRID(userRIDs[sam])
		var gs []sid.SID
		for _, g := range groups {
			gs = append(gs, sid.MustParse(g))
		}
		h.groups[u.String()] = gs
		return directory.Identity{DN: "CN=" + sam + ",OU=Special,DC=lab,DC=test", SID: u, SAM: sam, DisplayName: sam}, gs, nil
	}
	s.groupsOf = func(_ context.Context, sess *Session) ([]sid.SID, error) {
		g, ok := h.groups[sess.userSID.String()]
		if !ok {
			return nil, errors.New("no such user")
		}
		return g, nil
	}
	return h
}

// session creates a session directly (no sign-in) and returns its cookie.
func (h *harness) session(t *testing.T, sam string, st stage, mfaVerified bool) string {
	t.Helper()
	groups := fakeUsers[sam]
	u, _ := sid.MustParse(testDomain).WithRID(userRIDs[sam])
	var gs []sid.SID
	for _, g := range groups {
		gs = append(gs, sid.MustParse(g))
	}
	h.groups[u.String()] = gs
	sess := &Session{sam: sam, dn: "CN=" + sam + ",DC=lab,DC=test", userSID: u, displayName: sam, stage: st,
		cred: &directory.Credential{}, mfaVerified: mfaVerified, roles: h.s.roleSIDs.resolve(u, gs), rolesAt: h.now, groupSIDs: gs}
	if st == stageMustChange {
		sess.cred = nil
	}
	tok, err := h.s.sess.create(context.Background(), sess)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (h *harness) csrfOf(tok string) string {
	s := h.s.sess.byID[hashToken(tok)]
	if s == nil {
		return ""
	}
	return s.csrf
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

// do sends a request with the session cookie; POSTs carry the session's
// CSRF token unless the form sets "csrf" itself.
func (h *harness) do(method, path, tok string, form url.Values, opts ...reqOpt) *httptest.ResponseRecorder {
	var body io.Reader
	if method == http.MethodPost {
		if form == nil {
			form = url.Values{}
		}
		if _, ok := form["csrf"]; !ok && tok != "" {
			form.Set("csrf", h.csrfOf(tok))
		}
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://"+testHost+path, body)
	r.RemoteAddr = "192.0.2.10:40000"
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if tok != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	return w
}

// sentinel replaces every handler with one that records the call.
func (h *harness) sentinel() map[string]int {
	called := map[string]int{}
	var mu sync.Mutex
	for i := range h.s.routes {
		key := h.s.routes[i].method + " " + h.s.routes[i].pattern
		h.s.routes[i].h = func(rc *reqCtx) {
			mu.Lock()
			called[key]++
			mu.Unlock()
			rc.w.WriteHeader(299)
		}
	}
	h.s.buildMux()
	return called
}

func concretePath(p string) string {
	p = strings.ReplaceAll(p, "{guid}", "00112233-4455-6677-8899-aabbccddeeff")
	p = strings.ReplaceAll(p, "{id}", "pending-id-000000000000")
	return strings.ReplaceAll(p, "{$}", "")
}

// TestRouteGuards enumerates every route and checks who reaches its
// handler: anonymous visitors, each sign-in stage, and each role.
func TestRouteGuards(t *testing.T) {
	h := newHarness(t)
	called := h.sentinel()
	type actor struct {
		name  string
		tok   string
		stage stage
		roles Roles
		mfa   bool
	}
	actors := []actor{
		{name: "anonymous"},
		{name: "must-change", tok: h.session(t, "normal.user", stageMustChange, false), stage: stageMustChange},
		{name: "mfa-pending admin", tok: h.session(t, "lab.admin", stageMFA, false), stage: stageMFA},
		{name: "enroll-pending admin", tok: h.session(t, "lab.admin", stageEnroll, false), stage: stageEnroll},
		{name: "user", tok: h.session(t, "normal.user", stageFull, false), stage: stageFull},
		{name: "helpdesk", tok: h.session(t, "helpdesk.user", stageFull, true), stage: stageFull, roles: Roles{Helpdesk: true}, mfa: true},
		{name: "auditor", tok: h.session(t, "auditor.user", stageFull, true), stage: stageFull, roles: Roles{Auditor: true}, mfa: true},
		{name: "admin", tok: h.session(t, "lab.admin", stageFull, true), stage: stageFull, roles: Roles{Admin: true}, mfa: true},
	}
	for _, rt := range h.s.routes {
		for _, a := range actors {
			want := false
			switch rt.perm {
			case PermPublic:
				// An anonymous POST also needs the pre-session cookie
				// (double-submit CSRF); TestCSRF covers it.
				want = !(rt.method == "POST" && a.tok == "")
			case PermPreAuth:
				want = a.tok != "" && contains2(rt.stages, a.stage)
			default:
				want = a.stage == stageFull && a.roles.Has(rt.perm)
			}
			key := rt.method + " " + rt.pattern
			before := called[key]
			w := h.do(rt.method, concretePath(rt.pattern), a.tok, nil)
			got := called[key] > before
			if got != want {
				t.Errorf("%s %s as %s: handler reached=%v, want %v (status %d)", rt.method, rt.pattern, a.name, got, want, w.Code)
				continue
			}
			if !want && rt.perm != PermPublic {
				if w.Code != http.StatusSeeOther && w.Code != http.StatusForbidden {
					t.Errorf("%s %s as %s: status %d, want a redirect or 403", rt.method, rt.pattern, a.name, w.Code)
				}
				if a.stage == stageFull && rt.perm.privileged() && w.Code != http.StatusForbidden {
					t.Errorf("%s %s as %s: privileged refusal should be 403, got %d", rt.method, rt.pattern, a.name, w.Code)
				}
			}
		}
	}
	// Every refusal of a signed-in user is audited.
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "access.denied"}, 0, 1000)
	if len(evs) == 0 {
		t.Error("no access.denied events audited")
	}
}

func contains2(list []stage, s stage) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestAdminWithoutMFAIsRefused: an administrator whose session did not pass
// 2FA (role gained after signing in) never reaches an admin page.
func TestAdminWithoutMFAIsRefused(t *testing.T) {
	h := newHarness(t)
	called := h.sentinel()
	tok := h.session(t, "lab.admin", stageFull, false)
	w := h.do("GET", "/admin", tok, nil)
	if called["GET /admin"] != 0 || w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "mfa_required") {
		t.Fatalf("admin without 2FA: status %d location %q", w.Code, w.Header().Get("Location"))
	}
	if h.s.sess.get(context.Background(), tok) != nil {
		t.Fatal("session kept")
	}
}

// TestRoleRecheck: roles come from AD again after the cache TTL; losing the
// group loses access at the next privileged request.
func TestRoleRecheck(t *testing.T) {
	h := newHarness(t)
	called := h.sentinel()
	tok := h.session(t, "helpdesk.user", stageFull, true)
	if w := h.do("GET", "/admin/users", tok, nil); w.Code != 299 {
		t.Fatalf("helpdesk before: %d", w.Code)
	}
	u, _ := sid.MustParse(testDomain).WithRID(userRIDs["helpdesk.user"])
	h.groups[u.String()] = []sid.SID{sid.MustParse(testDomain + "-513")}
	h.now = h.now.Add(30 * time.Second) // within the cache TTL
	if w := h.do("GET", "/admin/users", tok, nil); w.Code != 299 {
		t.Fatalf("within TTL: %d", w.Code)
	}
	h.now = h.now.Add(31 * time.Second) // past 60 s
	if w := h.do("GET", "/admin/users", tok, nil); w.Code != http.StatusForbidden {
		t.Fatalf("after removal from the group: %d", w.Code)
	}
	if called["GET /admin/users"] != 2 {
		t.Fatalf("handler calls %d", called["GET /admin/users"])
	}
	// AD unreachable during a re-check: signed out, not allowed.
	delete(h.groups, u.String())
	h.now = h.now.Add(61 * time.Second)
	if w := h.do("GET", "/admin/users", tok, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("failed re-check: %d", w.Code)
	}
}

func TestCSRF(t *testing.T) {
	h := newHarness(t)
	called := h.sentinel()
	tok := h.session(t, "lab.admin", stageFull, true)
	cases := []struct {
		name string
		form url.Values
		opts []reqOpt
	}{
		{"no token", url.Values{"csrf": {""}}, nil},
		{"wrong token", url.Values{"csrf": {"x" + h.csrfOf(tok)[1:]}}, nil},
		{"cross-site fetch", nil, []reqOpt{withHeader("Sec-Fetch-Site", "cross-site")}},
		{"foreign origin", nil, []reqOpt{withHeader("Origin", "https://evil.example")}},
	}
	for _, c := range cases {
		w := h.do("POST", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/disable", tok, c.form, c.opts...)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d", c.name, w.Code)
		}
	}
	if called["POST /admin/users/{guid}/disable"] != 0 {
		t.Fatal("handler reached without a valid CSRF token")
	}
	w := h.do("POST", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/disable", tok, nil, withHeader("Sec-Fetch-Site", "same-origin"), withHeader("Origin", "https://"+testHost))
	if w.Code != 299 {
		t.Fatalf("valid request: %d", w.Code)
	}
	// Another session's token is worthless.
	other := h.session(t, "normal.user", stageFull, false)
	w = h.do("POST", "/me/sessions/signout-all", tok, url.Values{"csrf": {h.csrfOf(other)}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("token of another session: %d", w.Code)
	}
	// The sign-in form needs the pre-session cookie (double submit).
	w = h.do("POST", "/signin", "", url.Values{"csrf": {"abc"}, "username": {"normal.user"}, "password": {"x"}})
	if w.Code != http.StatusForbidden || called["POST /signin"] != 0 {
		t.Fatalf("sign-in without pre-session cookie: %d", w.Code)
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "security.csrf_rejected"}, 0, 100)
	if len(evs) < 5 {
		t.Fatalf("CSRF rejections audited: %d", len(evs))
	}
}

func TestAnonymousSurfaceAndHeaders(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/static/app.css", "/static/logo.svg", "/signin"} {
		w := h.do("GET", p, "", nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/", "/me", "/admin", "/admin/users", "/admin/audit/export", "/confirm/x", "/signin/2fa", "/signin/password"} {
		w := h.do("GET", p, "", nil)
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/signin") {
			t.Errorf("anonymous %s: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	for _, p := range []string{"/signin", "/static/app.css", "/nope"} {
		w := h.do("GET", p, "", nil)
		hd := w.Header()
		if !strings.Contains(hd.Get("Content-Security-Policy"), "script-src 'none'") ||
			!strings.Contains(hd.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.HasPrefix(hd.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: headers %v", p, hd)
		}
	}
	// The sign-in page sets a __Host- pre-session cookie with the right flags.
	w := h.do("GET", "/signin", "", nil)
	var pre *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == preCookie {
			pre = c
		}
	}
	if pre == nil || !pre.Secure || !pre.HttpOnly || pre.SameSite != http.SameSiteStrictMode || pre.Path != "/" || pre.Domain != "" {
		t.Fatalf("pre-session cookie %+v", pre)
	}
	if body := w.Body.String(); strings.Contains(body, "<script") || strings.Contains(body, "style=") {
		t.Fatal("inline script or style in the sign-in page")
	}
}

// signin posts the sign-in form like a browser: GET for the pre-session
// cookie, then POST.
func (h *harness) signin(t *testing.T, username, password, enroll string) *httptest.ResponseRecorder {
	t.Helper()
	w := h.do("GET", "/signin", "", nil)
	var pre string
	for _, c := range w.Result().Cookies() {
		if c.Name == preCookie {
			pre = c.Value
		}
	}
	form := url.Values{"csrf": {pre}, "username": {username}, "password": {password}}
	if enroll != "" {
		form.Set("enroll", enroll)
	}
	return h.do("POST", "/signin", "", form, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: preCookie, Value: pre}) })
}

func sessionFrom(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

func TestSigninRateLimits(t *testing.T) {
	h := newHarness(t)
	// Per account: after 5 failures conductor stops asking AD.
	for i := range 5 {
		if w := h.signin(t, "victim", "wrong", ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	calls := h.backend.calls
	w := h.signin(t, "victim", "wrong", "")
	if w.Code != http.StatusTooManyRequests || h.backend.calls != calls {
		t.Fatalf("6th attempt: %d (backend calls %d → %d)", w.Code, calls, h.backend.calls)
	}
	// Another account is unaffected.
	if w := h.signin(t, "normal.user", "x", ""); w.Code != http.StatusSeeOther {
		t.Fatalf("other account: %d", w.Code)
	}
	// Per address.
	h2 := newHarness(t)
	h2.s.ipLimit.Allow("signin:192.0.2.10") // warm up
	for i := 0; i < 1000; i++ {
		h2.s.ipLimit.Allow("signin:192.0.2.10")
	}
	if w := h2.signin(t, "normal.user", "x", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("per-address limit: %d", w.Code)
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "signin.rate_limited"}, 0, 10)
	if len(evs) == 0 {
		t.Fatal("rate limiting not audited")
	}
}

func TestSigninOutcomes(t *testing.T) {
	h := newHarness(t)
	h.backend.results["must.change"] = mustChangeErr()
	h.backend.results["locked.user"] = &ad.AuthError{Reason: ad.ReasonAccountLocked, Mechanism: "kerberos"}
	h.backend.results["disabled.user"] = &ad.AuthError{Reason: ad.ReasonAccountDisabled, Mechanism: "kerberos"}
	h.backend.results["expired.account"] = &ad.AuthError{Reason: ad.ReasonAccountExpired, Mechanism: "kerberos"}
	// An "expired" answer that AD did not verify is a wrong password.
	h.backend.results["unverified"] = &ad.AuthError{Reason: ad.ReasonPasswordExpired, Mechanism: "kerberos"}

	w := h.signin(t, "must.change", "right", "")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/password" {
		t.Fatalf("must change: %d %q", w.Code, w.Header().Get("Location"))
	}
	tok := sessionFrom(w)
	// Only the change page is reachable in that stage.
	if w := h.do("GET", "/me", tok, nil); w.Header().Get("Location") != "/signin/password" {
		t.Fatalf("must-change session reached /me: %d", w.Code)
	}
	w = h.do("POST", "/signin/password", tok, url.Values{"current": {"wrong"}, "new": {"N3w-pass"}, "confirm": {"N3w-pass"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "current password is not correct") {
		t.Fatalf("wrong old password: %d", w.Code)
	}
	w = h.do("POST", "/signin/password", tok, url.Values{"current": {"right"}, "new": {"N3w-pass"}, "confirm": {"N3w-pass"}})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "password_changed") || !h.backend.changed["must.change"] {
		t.Fatalf("change: %d %q", w.Code, w.Header().Get("Location"))
	}

	for user, want := range map[string]string{"locked.user": "locked", "disabled.user": "disabled", "expired.account": "expired",
		"unverified": "Wrong username or password", "nobody": "Wrong username or password"} {
		w := h.signin(t, user, "pw", "")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d, body lacks %q", user, w.Code, want)
		}
	}

	// Regular user, optional 2FA policy: straight in.
	w = h.signin(t, "normal.user", "pw", "")
	if w.Header().Get("Location") != "/me" {
		t.Fatalf("normal user: %q", w.Header().Get("Location"))
	}
	// Administrator without 2FA and without a link: refused.
	w = h.signin(t, "lab.admin", "pw", "")
	if w.Code != http.StatusForbidden || sessionFrom(w) != "" {
		t.Fatalf("admin without link: %d", w.Code)
	}
	// Helpdesk without 2FA: must enroll (TOFU for delegated roles).
	w = h.signin(t, "helpdesk.user", "pw", "")
	if w.Header().Get("Location") != "/signin/enroll" {
		t.Fatalf("helpdesk: %q", w.Header().Get("Location"))
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "signin."}, 0, 100)
	if len(evs) < 8 {
		t.Fatalf("sign-ins audited: %d", len(evs))
	}
}

func mustChangeErr() error {
	// What ad.SignIn returns for a must-change account with the right
	// password (verified by the confirming kadmin/changepw exchange).
	return ad.ClassifyBindError(&ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials,
		Err: errors.New("80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext error, data 773, v4563")})
}
