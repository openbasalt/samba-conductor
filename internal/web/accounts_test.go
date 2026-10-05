package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// accountsHarness: a regular user whose session passed a second factor
// just now, and conductor-sync offering an activation.
func accountsHarness(t *testing.T) (*harness, *fakeSync, string) {
	t.Helper()
	h, fs := syncHarness(t)
	fs.account = syncapi.TargetAccount{Target: "google", Title: "Google Workspace", State: syncapi.AccountNotActivated, CanActivate: true,
		Address: "normal.user@example.com", Capabilities: syncapi.Capabilities{OnDemandCreate: true, SetPassword: true, PasswordRules: true, Status: true},
		Rules: syncapi.PasswordRules{MinLength: 12, MaxLength: 100, PrintableASCII: true}, ActionsLeft: 3, PasswordReason: syncapi.ReasonNotLinked}
	tok := h.session(t, "normal.user", stageFull, true)
	h.s.sess.byID[hashToken(tok)].mfaAt = h.now
	return h, fs, tok
}

func TestAccountsPage(t *testing.T) {
	h, fs, tok := accountsHarness(t)
	w := h.do("GET", "/me/accounts", tok, nil)
	body := w.Body.String()
	for _, want := range []string{`data-e2e="nav-link-accounts"`, `data-e2e="accounts-card-google"`, "Google Workspace", "normal.user@example.com",
		`data-e2e="accounts-badge-state-google"`, `data-e2e="accounts-btn-activate-google"`, `action="/me/accounts/google/activate"`,
		`data-e2e="accounts-text-left-google"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Typed passwords only when the target allows them.
	if strings.Contains(body, "accounts-details-chosen-google") {
		t.Error("chosen password form shown while not allowed")
	}
	if r := fs.last(syncapi.OpAccountStatus); r == nil || r.Actor.User != "normal.user" || r.Actor.SID == "" {
		t.Fatalf("actor %+v", r)
	}
	// Portuguese.
	pt := h.do("GET", "/me/accounts?lang=pt-BR", tok, nil).Body.String()
	if !strings.Contains(pt, "Contas conectadas") || !strings.Contains(pt, "Ativar com uma senha gerada") {
		t.Error("pt-BR page not translated")
	}
	// A linked, adopted account: the reason the reset is not offered.
	fs.account.State, fs.account.CanActivate, fs.account.ActivateReason = syncapi.AccountActive, false, syncapi.ReasonAlreadyActive
	fs.account.Origin, fs.account.PasswordReason = syncapi.OriginAdopted, syncapi.ReasonAdopted
	body = h.do("GET", "/me/accounts?lang=en", tok, nil).Body.String()
	if strings.Contains(body, "accounts-btn-") || !strings.Contains(body, `data-e2e="accounts-text-password-reason-google"`) ||
		!strings.Contains(body, "existed before the sync") {
		t.Errorf("adopted account page: %s", body)
	}
	// Without the sync section: no entry, a note.
	h.s.sync = nil
	body = h.do("GET", "/me/accounts", tok, nil).Body.String()
	if !strings.Contains(body, "accounts-text-disabled") || strings.Contains(body, `data-e2e="nav-link-accounts"`) {
		t.Error("disabled sync still offers connected accounts")
	}
}

// TestAccountsActivateShowsPasswordOnce: the activation is confirmed, sent
// for the signed-in user, and the generated password is shown once (no
// cache, the copy script allowed), never audited.
func TestAccountsActivateShowsPasswordOnce(t *testing.T) {
	h, fs, tok := accountsHarness(t)
	const pw = "Kq7v-Xm2p-Rt4w-Hn8c"
	fs.action = syncapi.AccountActionResult{Password: pw, Account: syncapi.TargetAccount{Target: "google", State: syncapi.AccountActive,
		Address: "normal.user@example.com", Origin: syncapi.OriginCreated}}
	w := h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"generate"}})
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") || fs.count(syncapi.OpAccountActivate) != 0 {
		t.Fatalf("not a confirmation: %d %q", w.Code, loc)
	}
	cp := h.do("GET", loc, tok, nil).Body.String()
	if strings.Contains(cp, "confirm-text-reauth") || !strings.Contains(cp, "account.activate") || !strings.Contains(cp, "confirm-text-warning") {
		t.Fatalf("confirmation page (fresh second factor): %s", cp)
	}
	w = h.do("POST", loc, tok, nil)
	sec := w.Header().Get("Location")
	if !strings.HasPrefix(sec, "/me/accounts/secret/") {
		t.Fatalf("after confirm: %d %q", w.Code, sec)
	}
	r := fs.last(syncapi.OpAccountActivate)
	if r == nil || r.Actor.User != "normal.user" || !strings.Contains(string(r.Params), `"mode":"generate"`) || strings.Contains(string(r.Params), "password") {
		t.Fatalf("request %+v", r)
	}
	w = h.do("GET", sec, tok, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, pw) || !strings.Contains(body, `data-e2e="accounts-text-once"`) ||
		!strings.Contains(body, `data-copy="new-password"`) || w.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "'nonce-") {
		t.Fatalf("secret page %d %v: %s", w.Code, w.Header(), body)
	}
	// Once only.
	if w := h.do("GET", sec, tok, nil); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), pw) {
		t.Fatalf("second view: %d", w.Code)
	}
	if strings.Contains(h.auditText(t), pw) {
		t.Fatal("the password is in the audit")
	}
	if !strings.Contains(h.auditText(t), "self.account_activate") {
		t.Fatal("activation not audited")
	}
	// Another user cannot open it (the reference lives in the session).
	other := h.session(t, "helpdesk.user", stageFull, true)
	if w := h.do("GET", sec, other, nil); w.Code != http.StatusNotFound {
		t.Fatalf("other session: %d", w.Code)
	}
}

// TestAccountsStepUp: a second factor older than a few minutes asks for the
// password and a code again; without them nothing is sent.
func TestAccountsStepUp(t *testing.T) {
	h, fs, tok := accountsHarness(t)
	secret := h.enrollTOTP(t, "normal.user")
	fs.action = syncapi.AccountActionResult{Password: "Zz9z-Yy8y-Xx7x-Ww6w", Account: syncapi.TargetAccount{Target: "google", State: syncapi.AccountActive}}
	h.now = h.now.Add(accountsFreshMFA + time.Minute)
	loc := h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"generate"}}).Header().Get("Location")
	if cp := h.do("GET", loc, tok, nil).Body.String(); !strings.Contains(cp, "confirm-text-reauth") {
		t.Fatal("no step-up for a stale second factor")
	}
	if w := h.do("POST", loc, tok, nil); w.Code != http.StatusUnauthorized || fs.count(syncapi.OpAccountActivate) != 0 {
		t.Fatalf("confirm without re-authentication: %d, %d calls", w.Code, fs.count(syncapi.OpAccountActivate))
	}
	if res := h.confirmWith(t, tok, loc, secret); !strings.HasPrefix(res.Header.Get("Location"), "/me/accounts/secret/") {
		t.Fatalf("after step-up: %q", res.Header.Get("Location"))
	}
	// The step-up refreshed the second factor: the next action needs none.
	fs.account.State, fs.account.CanActivate, fs.account.CanSetPassword = syncapi.AccountActive, false, true
	loc = h.do("POST", "/me/accounts/google/password", tok, url.Values{"mode": {"generate"}}).Header().Get("Location")
	if cp := h.do("GET", loc, tok, nil).Body.String(); strings.Contains(cp, "confirm-text-reauth") {
		t.Fatal("step-up asked again right after one")
	}
}

// TestAccountsChosenPassword: typed passwords are checked (match, length)
// before anything is sent, go to conductor-sync once, and are neither shown
// nor audited.
func TestAccountsChosenPassword(t *testing.T) {
	h, fs, tok := accountsHarness(t)
	fs.account.State, fs.account.CanActivate, fs.account.CanSetPassword = syncapi.AccountActive, false, true
	fs.account.ChosenPassword = true
	fs.action = syncapi.AccountActionResult{Account: syncapi.TargetAccount{Target: "google", State: syncapi.AccountActive}}
	if body := h.do("GET", "/me/accounts", tok, nil).Body.String(); !strings.Contains(body, "accounts-details-chosen-google") ||
		!strings.Contains(body, `minlength="12"`) {
		t.Fatal("chosen password form missing")
	}
	post := func(pw, confirm string) string {
		return h.do("POST", "/me/accounts/google/password", tok, url.Values{"mode": {"chosen"}, "password": {pw}, "confirm": {confirm}}).Header().Get("Location")
	}
	if loc := post("a long passphrase", "a long passphrasf"); loc != "/me/accounts" {
		t.Fatalf("mismatch: %q", loc)
	}
	if loc := post("short", "short"); loc != "/me/accounts" {
		t.Fatalf("too short: %q", loc)
	}
	if body := h.do("GET", "/me/accounts", tok, nil).Body.String(); !strings.Contains(body, "from 12 to 100 characters") {
		t.Fatal("length message missing")
	}
	const pw = "my own long passphrase 7"
	loc := post(pw, pw)
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("chosen: %q", loc)
	}
	cp := h.do("GET", loc, tok, nil).Body.String()
	if strings.Contains(cp, pw) || !strings.Contains(cp, "typed by you") {
		t.Fatalf("confirmation page: %s", cp)
	}
	w := h.do("POST", loc, tok, nil)
	if w.Header().Get("Location") != "/me/accounts" || fs.chosen != pw {
		t.Fatalf("after confirm: %q, sent %v", w.Header().Get("Location"), fs.chosen == pw)
	}
	if body := h.do("GET", "/me/accounts", tok, nil).Body.String(); !strings.Contains(body, "was changed") || strings.Contains(body, pw) {
		t.Fatal("done message missing or password shown")
	}
	if strings.Contains(h.auditText(t), pw) {
		t.Fatal("the typed password is in the audit")
	}
}

// TestAccountsRefusals: no second factor, a refusal by conductor-sync with
// its reason, and the rate limit, each a plain sentence.
func TestAccountsRefusals(t *testing.T) {
	h, fs, _ := accountsHarness(t)
	nomfa := h.session(t, "normal.user", stageFull, false)
	if body := h.do("GET", "/me/accounts", nomfa, nil).Body.String(); !strings.Contains(body, "accounts-text-mfa-needed") || strings.Contains(body, "accounts-btn-") {
		t.Fatal("a session without a second factor is offered actions")
	}
	if loc := h.do("POST", "/me/accounts/google/activate", nomfa, url.Values{"mode": {"generate"}}).Header().Get("Location"); loc != "/me/accounts" ||
		fs.count(syncapi.OpAccountActivate) != 0 {
		t.Fatalf("no second factor: %q", loc)
	}
	tok := h.session(t, "normal.user", stageFull, true)
	h.s.sess.byID[hashToken(tok)].mfaAt = h.now
	fs.fail[syncapi.OpAccountActivate] = &syncapi.Error{Code: syncapi.CodeForbidden, Message: "an account with this address exists", Details: []string{syncapi.ReasonExistingAccount}}
	loc := h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"generate"}}).Header().Get("Location")
	h.do("POST", loc, tok, nil)
	if body := h.do("GET", "/me/accounts", tok, nil).Body.String(); !strings.Contains(body, "the next sync links it to you") {
		t.Fatal("refusal reason not shown")
	}
	fs.fail[syncapi.OpAccountActivate] = &syncapi.Error{Code: syncapi.CodeRateLimited, Message: "too many"}
	loc = h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"generate"}}).Header().Get("Location")
	h.do("POST", loc, tok, nil)
	if body := h.do("GET", "/me/accounts", tok, nil).Body.String(); !strings.Contains(body, "Too many actions in the last hour") {
		t.Fatal("rate limit not shown")
	}
	// Not allowed now (status): refused before any confirmation.
	fs.account.CanActivate, fs.account.ActivateReason = false, syncapi.ReasonDryRun
	if loc := h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"generate"}}).Header().Get("Location"); loc != "/me/accounts" {
		t.Fatalf("dry-run: %q", loc)
	}
	// A bad target or mode.
	if w := h.do("POST", "/me/accounts/Google%20Workspace/activate", tok, url.Values{"mode": {"generate"}}); w.Code != http.StatusNotFound {
		t.Fatalf("bad target: %d", w.Code)
	}
	if w := h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"other"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mode: %d", w.Code)
	}
}

// TestAccountsConfirmHint: the confirmation of a connected-account action
// says the change goes to the target through conductor-sync (named as
// conductor-sync reports it), not that LDAP writes go to the DC; real LDAP
// writes keep the LDAP hint and other actions get a neutral one.
func TestAccountsConfirmHint(t *testing.T) {
	h, fs, tok := accountsHarness(t)
	// The display name comes from conductor-sync, nothing is hardcoded.
	fs.account.Title = "Example Directory"
	loc := h.do("POST", "/me/accounts/google/activate", tok, url.Values{"mode": {"generate"}}).Header().Get("Location")
	cp := h.do("GET", loc, tok, nil).Body.String()
	if !strings.Contains(cp, "This sends the change to Example Directory through the sync service") || strings.Contains(cp, "LDAP writes are sent") {
		t.Fatalf("activation hint: %s", cp)
	}
	fs.account.State, fs.account.CanActivate, fs.account.CanSetPassword = syncapi.AccountActive, false, true
	loc = h.do("POST", "/me/accounts/google/password", tok, url.Values{"mode": {"generate"}}, withHeader("Accept-Language", "pt-BR")).Header().Get("Location")
	cp = h.do("GET", loc, tok, nil, withHeader("Accept-Language", "pt-BR")).Body.String()
	if !strings.Contains(cp, "Isto envia a alteração para Example Directory pelo serviço de sincronização") || strings.Contains(cp, "gravações LDAP são enviadas") {
		t.Fatalf("password hint (pt-BR): %s", cp)
	}
	// An LDAP write keeps the LDAP hint; a non-LDAP action without its own
	// hint gets the neutral one.
	sess := h.s.sess.byID[hashToken(tok)]
	op, err := ad.UnlockUser("CN=x,OU=People,DC=lab,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	sess.mu.Lock()
	sess.pending["ldapop0000000000000000"] = &pendingOp{id: "ldapop0000000000000000", created: h.now, perm: PermSelf, op: op,
		preview: op.Preview().String(), back: "/"}
	sess.pending["runop00000000000000000"] = &pendingOp{id: "runop00000000000000000", created: h.now, perm: PermSelf,
		run: func(context.Context, *reqCtx) error { return nil }, preview: "x", back: "/"}
	sess.mu.Unlock()
	if cp := h.do("GET", "/confirm/ldapop0000000000000000", tok, nil).Body.String(); !strings.Contains(cp, "These LDAP writes are sent") {
		t.Fatalf("LDAP hint lost: %s", cp)
	}
	if cp := h.do("GET", "/confirm/runop00000000000000000", tok, nil).Body.String(); strings.Contains(cp, "LDAP") ||
		!strings.Contains(cp, "This is the change conductor carries out") {
		t.Fatalf("neutral hint: %s", cp)
	}
}
