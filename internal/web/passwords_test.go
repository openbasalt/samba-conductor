package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

const (
	normalSID  = testDomain + "-1101"
	inviteeSID = testDomain + "-1201"
	privSID    = testDomain + "-1202"
	outsideSID = testDomain + "-1203"
	nomailSID  = testDomain + "-1204"
)

// adminRC is a request context of a signed-in administrator, for the
// functions that run behind a confirmation.
func (h *pwHarness) adminRC(t *testing.T) *reqCtx {
	t.Helper()
	tok := h.session(t, "lab.admin", stageFull, true)
	r, _ := http.NewRequest("GET", "https://conductor.test/", nil)
	return &reqCtx{s: h.s, r: r, sess: h.s.sess.byID[hashToken(tok)], lang: "en", ip: "192.0.2.1", roles: Roles{Admin: true}}
}

// invite issues an invitation for new.person as an administrator.
func (h *pwHarness) invite(t *testing.T) string {
	t.Helper()
	rc := h.adminRC(t)
	p := &pendingOp{preview: "x"}
	if err := h.s.inviteRun(p, inviteeSID)(context.Background(), rc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.preview, "# token ") {
		t.Fatalf("preview lacks the token: %s", p.preview)
	}
	m := h.mailsOf(t, mail.TemplateInvitation)
	if len(m) == 0 {
		t.Fatal("no invitation queued")
	}
	return linkFrom(t, m[len(m)-1].Text)
}

func TestInvitationEndToEnd(t *testing.T) {
	h := newPWHarness(t)
	link := h.invite(t)
	inv := h.mailsOf(t, mail.TemplateInvitation)[0]
	if inv.To != "new.person@example.org" || !strings.HasPrefix(inv.Reference, "token:") || !strings.Contains(inv.Text, "new.person") {
		t.Fatalf("invitation %+v", inv)
	}
	lt, err := h.st.GetLinkToken(context.Background(), strings.TrimPrefix(inv.Reference, "token:"))
	if err != nil || lt.IssuerName != "lab.admin" || !lt.ExpiresAt.Equal(h.now.Add(72*time.Hour)) {
		t.Fatalf("link token %+v %v", lt, err)
	}

	b := h.browser()
	// GET validates only: twice, nothing consumed.
	for range 2 {
		r := b.do("GET", link, nil)
		page := body(t, r)
		if r.StatusCode != http.StatusOK || !strings.Contains(page, `data-e2e="link-btn-start"`) || !strings.Contains(page, "new.person") {
			t.Fatalf("link page %d:\n%s", r.StatusCode, page)
		}
		if r.Header.Get("Referrer-Policy") != "no-referrer" || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("headers %v", r.Header)
		}
		mustTagE2E(t, page)
	}
	if h.prov.count(provapi.OpPasswordSet) != 0 || h.prov.count(provapi.OpTokenCheck) != 2 {
		t.Fatal("GET did more than a check")
	}
	if a := h.prov.last(provapi.OpTokenCheck).Actor; a.User != provapi.PublicUser || a.SID != "" || a.IP != b.ip {
		t.Fatalf("public actor %+v", a)
	}
	// Start: the token moves into the record and its cookie.
	r := b.do("POST", link+"/start", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/link/password" {
		t.Fatalf("start: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	var lc *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == linkCookie {
			lc = c
		}
	}
	if lc == nil || !lc.Secure || !lc.HttpOnly || lc.SameSite != http.SameSiteStrictMode || lc.Path != "/" || lc.MaxAge != 600 {
		t.Fatalf("link cookie %+v", lc)
	}
	// Steps out of order go back to the current one.
	if r := b.do("GET", "/link/done", nil); r.Header.Get("Location") != "/link/password" {
		t.Fatalf("done before the password: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	page := body(t, b.do("GET", "/link/password", nil))
	mustTagE2E(t, page)
	if r := b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"other"}}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatch: %d", r.StatusCode)
	}
	// A policy refusal is explained and the step can be retried.
	h.prov.policy = provapi.ReasonHistory
	r = b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body(t, r), "was used before") {
		t.Fatalf("policy: %d", r.StatusCode)
	}
	h.prov.policy = ""
	r = b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/link/enroll" || !h.prov.set[inviteeSID] {
		t.Fatalf("password: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if h.prov.last(provapi.OpPasswordSet).Actor.User != provapi.PublicUser {
		t.Fatal("password.set not made for the public actor")
	}
	// Optional second factor: the enrollment can be skipped.
	page = body(t, b.do("GET", "/link/enroll", nil))
	if !strings.Contains(page, `data-e2e="enroll-btn-skip"`) || !strings.Contains(page, `action="/link/enroll"`) {
		t.Fatalf("enroll page:\n%s", page)
	}
	mustTagE2E(t, page)
	r = b.do("POST", "/link/enroll/skip", nil)
	if r.Header.Get("Location") != "/link/done" || h.prov.count(provapi.OpInviteComplete) != 1 || !h.prov.users[inviteeSID].Enabled {
		t.Fatalf("skip: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	r = b.do("GET", "/link/done", nil)
	page = body(t, r)
	if r.StatusCode != http.StatusOK || !strings.Contains(page, `data-e2e="link-text-done"`) || b.cookies[linkCookie] != "" {
		t.Fatalf("done: %d %v\n%s", r.StatusCode, b.cookies, page)
	}
	// Shown once; the link is used.
	if page := body(t, b.do("GET", "/link/done", nil)); !strings.Contains(page, `data-e2e="link-text-invalid"`) {
		t.Fatal("done page shown twice")
	}
	if page := body(t, b.do("GET", link, nil)); !strings.Contains(page, `data-e2e="link-text-invalid"`) {
		t.Fatal("used link still offered")
	}
	// The person is told about the new password.
	if n := h.mailsOf(t, mail.TemplatePasswordChanged); len(n) != 1 || n[0].To != "new.person@example.org" || !strings.Contains(n[0].Text, b.ip) {
		t.Fatalf("notification %+v", n)
	}
	acts := h.auditActions(t)
	for _, want := range []string{"invite.opened:ok", "invite.password_refused:denied", "invite.password_set:ok", "invite.completed:ok"} {
		if !hasAction(acts, want) {
			t.Errorf("audit lacks %s: %v", want, acts)
		}
	}
	if strings.Contains(h.auditText(t), "N3w-pass!") {
		t.Fatal("password in the audit log")
	}
}

func TestInvitationEnrollmentRequired(t *testing.T) {
	h := newPWHarness(t, func(c *config.Config) { c.MFA.Policy = config.MFARequired })
	link := h.invite(t)
	b := h.browser()
	b.do("POST", link+"/start", nil)
	b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	page := body(t, b.do("GET", "/link/enroll", nil))
	if strings.Contains(page, "enroll-btn-skip") {
		t.Fatal("skip offered while required")
	}
	if r := b.do("POST", "/link/enroll/skip", nil); r.StatusCode != http.StatusForbidden || h.prov.count(provapi.OpInviteComplete) != 0 {
		t.Fatalf("skip while required: %d", r.StatusCode)
	}
	if r := b.do("GET", "/link/enroll/qr.png", nil); r.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("QR: %v", r.Header)
	}
	rec := h.s.links.get(b.cookies[linkCookie], h.now)
	if r := b.do("POST", "/link/enroll", url.Values{"code": {"000000"}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", r.StatusCode)
	}
	code := totp.Code(rec.sess.enrollSecret, totp.Step(h.now))
	r := b.do("POST", "/link/enroll", url.Values{"code": {code}})
	if r.Header.Get("Location") != "/link/done" || !h.prov.users[inviteeSID].Enabled {
		t.Fatalf("enroll: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if _, err := h.st.GetTOTP(context.Background(), inviteeSID); err != nil {
		t.Fatal("TOTP not stored")
	}
	page = body(t, b.do("GET", "/link/done", nil))
	if strings.Count(page, `data-e2e="link-text-code"`) < 5 {
		t.Fatalf("recovery codes not shown:\n%s", page)
	}
	if !hasAction(h.auditActions(t), "invite.enrolled:ok") {
		t.Fatal("enrollment not audited")
	}
}

// TestInvitationResumesAfterPassword: an invitation whose password is set
// (the record expired) resumes at what is left.
func TestInvitationResumesAfterPassword(t *testing.T) {
	h := newPWHarness(t, func(c *config.Config) { c.MFA.Policy = config.MFAOff })
	link := h.invite(t)
	b := h.browser()
	b.do("POST", link+"/start", nil)
	h.prov.fail[provapi.OpInviteComplete] = &provapi.Error{Code: provapi.CodeUnavailable, Message: "down"}
	r := b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("complete while the provisioner is down: %d", r.StatusCode)
	}
	delete(h.prov.fail, provapi.OpInviteComplete)
	h.now = h.now.Add(11 * time.Minute) // the record is gone
	b2 := h.browser()
	b2.do("GET", link, nil)
	r = b2.do("POST", link+"/start", nil)
	if r.Header.Get("Location") != "/link/done" || !h.prov.users[inviteeSID].Enabled {
		t.Fatalf("resume: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

func TestLinkInvalidIsUniform(t *testing.T) {
	h := newPWHarness(t)
	link := h.invite(t)
	// A revoked and an expired token, an unknown and a malformed one.
	h.prov.mu.Lock()
	for _, tk := range h.prov.tokens {
		tk.state = provapi.StateRevoked
	}
	h.prov.mu.Unlock()
	expired := h.invite(t)
	h.prov.mu.Lock()
	h.prov.tokens[strings.TrimPrefix(expired, "/link/")].expires = h.now
	h.prov.mu.Unlock()
	var first string
	for i, path := range []string{link, expired, "/link/" + strings.Repeat("Q", 43), "/link/short", "/link/" + strings.Repeat("%2F", 20)} {
		b := h.browser()
		before := h.prov.count(provapi.OpTokenCheck)
		r := b.do("GET", path, nil)
		page := body(t, r)
		if r.StatusCode != http.StatusOK || !strings.Contains(page, `data-e2e="link-text-invalid"`) {
			t.Fatalf("%s: %d", path, r.StatusCode)
		}
		if h.prov.count(provapi.OpTokenCheck) != before+1 {
			t.Errorf("%s: token.check not called", path)
		}
		if i == 0 {
			first = page
		} else if page != first {
			t.Errorf("%s: a different page", path)
		}
		// POST start: the same.
		r = b.do("POST", path+"/start", nil)
		if p := body(t, r); r.StatusCode != http.StatusOK || p != first {
			t.Errorf("%s start: %d", path, r.StatusCode)
		}
	}
	if !hasAction(h.auditActions(t), "link.refused:denied") {
		t.Fatal("refusals not audited")
	}
	// Ten failed checks per address per hour, then no more checks.
	b := h.browser()
	b.ip = "203.0.113.9"
	for range linkFailuresPerHour {
		b.do("GET", "/link/"+strings.Repeat("Z", 43), nil)
	}
	before := h.prov.count(provapi.OpTokenCheck)
	if page := body(t, b.do("GET", "/link/"+strings.Repeat("Z", 43), nil)); !strings.Contains(page, "link-text-invalid") ||
		h.prov.count(provapi.OpTokenCheck) != before {
		t.Fatal("checks not limited per address")
	}
	// Link pages without a record: the neutral page, no CSRF error.
	if page := body(t, h.browser().do("POST", "/link/password", url.Values{"new": {"x"}, "confirm": {"x"}})); !strings.Contains(page, "link-text-invalid") {
		t.Fatal("orphan POST")
	}
}

// TestLinkConductorLifetime: conductor's own, shorter lifetime wins.
func TestLinkConductorLifetime(t *testing.T) {
	h := newPWHarness(t)
	h.setSettings(t, func(p *passwordSettings) { p.InviteHours = 1 })
	link := h.invite(t)
	h.now = h.now.Add(61 * time.Minute)
	if page := body(t, h.browser().do("GET", link, nil)); !strings.Contains(page, "link-text-invalid") {
		t.Fatal("link valid past conductor's lifetime")
	}
	if r := h.prov.last(provapi.OpTokenRevoke); r == nil || !strings.Contains(string(r.Params), `"expired"`) {
		t.Fatalf("not revoked: %+v", r)
	}
}

func TestLinksNeedEverything(t *testing.T) {
	h := newPWHarness(t, func(c *config.Config) { c.Server.PublicURL = "" })
	if _, err := h.s.issueLink(context.Background(), issueRequest{actor: publicActor("x", ""), sid: normalSID, purpose: provapi.PurposeReset}); err != errNoPublicURL {
		t.Fatalf("no public URL: %v", err)
	}
	h2 := newPWHarness(t)
	h2.s.prov = nil
	if page := body(t, h2.browser().do("GET", "/link/"+strings.Repeat("A", 43), nil)); !strings.Contains(page, "link-text-invalid") {
		t.Fatal("link page without the provisioner")
	}
	rc := h2.adminRC(t)
	if v := h2.s.inviteInfo(context.Background(), rc, normalSID, false); len(v.Missing) != 1 || v.Missing[0] != "provisioner" {
		t.Fatalf("missing %+v", v)
	}
	// No address at all: the token is revoked.
	h3 := newPWHarness(t)
	_, err := h3.s.issueLink(context.Background(), issueRequest{actor: publicActor("x", ""), sid: nomailSID, purpose: provapi.PurposeReset})
	if err != errNoAddress || h3.prov.count(provapi.OpTokenRevoke) != 1 {
		t.Fatalf("no address: %v", err)
	}
}

func TestInviteInfoAndRun(t *testing.T) {
	h := newPWHarness(t)
	rc := h.adminRC(t)
	ctx := context.Background()
	cases := map[string]string{normalSID: "", privSID: "invite.reason.privileged", outsideSID: "invite.reason.out_of_scope", nomailSID: "invite.reason.no_mail"}
	for s, want := range cases {
		v := h.s.inviteInfo(ctx, rc, s, false)
		if v.Reason != want || v.Can != (want == "") || v.Err != "" {
			t.Errorf("%s: %+v", s, v)
		}
	}
	if v := h.s.inviteInfo(ctx, rc, privSID, false); len(v.Kinds) != 1 || v.Kinds[0] != "group" {
		t.Fatalf("kinds %+v", v.Kinds)
	}
	// Helpdesk on an account conductor protects: refused.
	rc.roles = Roles{Helpdesk: true}
	if v := h.s.inviteInfo(ctx, rc, normalSID, true); v.Can || v.Reason != "err.protected" {
		t.Fatalf("protected %+v", v)
	}
	rc.roles = Roles{Admin: true}
	// An open token is listed with Revoke.
	h.invite(t)
	v := h.s.inviteInfo(ctx, rc, inviteeSID, false)
	if len(v.Tokens) != 1 || !v.Tokens[0].Open {
		t.Fatalf("tokens %+v", v.Tokens)
	}
	// The provisioner refuses a privileged account even if asked.
	p := &pendingOp{}
	err := h.s.inviteRun(p, privSID)(ctx, rc)
	if provapi.ErrorCodeOf(err) != provapi.CodePrivileged || h.s.adErrorKey(err) != "prov.err.privileged" || !strings.Contains(p.preview, "privileged") {
		t.Fatalf("privileged: %v %q", err, p.preview)
	}
	h.prov.fail[provapi.OpUserCheck] = &provapi.Error{Code: provapi.CodeUnavailable, Message: "down"}
	if v := h.s.inviteInfo(ctx, rc, normalSID, false); v.Err == "" || v.Can {
		t.Fatalf("provisioner down: %+v", v)
	}
	// The scope of new accounts.
	if ok, err := h.s.inviteScopeOK(ctx, rc, "ou=sales,OU=People,DC=lab,DC=test"); !ok || err != nil {
		t.Fatal("OU below the scope refused")
	}
	if ok, _ := h.s.inviteScopeOK(ctx, rc, "OU=Staff,DC=lab,DC=test"); ok {
		t.Fatal("OU outside the scope accepted")
	}
	if ok, _ := h.s.inviteScopeOK(ctx, rc, "OU=XPeople,DC=lab,DC=test"); ok {
		t.Fatal("suffix trick accepted")
	}
	f := map[string]string{"mail": "x@example.org", "parent": "OU=People,DC=lab,DC=test"}
	if k := h.s.inviteNewCheck(ctx, rc, f); k != "" {
		t.Fatalf("new account check: %s", k)
	}
	if k := h.s.inviteNewCheck(ctx, rc, map[string]string{"parent": "OU=People,DC=lab,DC=test"}); k != "invite.err.mail_required" {
		t.Fatalf("no mail: %s", k)
	}
	if k := h.s.inviteNewCheck(ctx, rc, map[string]string{"mail": "x@example.org", "parent": "CN=Users,DC=lab,DC=test"}); k != "invite.reason.out_of_scope" {
		t.Fatalf("out of scope: %s", k)
	}
}

func TestAutomaticReissue(t *testing.T) {
	h := newPWHarness(t)
	ctx := context.Background()
	h.setSettings(t, func(p *passwordSettings) { p.InviteHours = 1 })
	h.invite(t)
	h.now = h.now.Add(2 * time.Hour)
	h.s.sweepInvites(ctx) // off: nothing
	if n := len(h.mailsOf(t, mail.TemplateInvitation)); n != 1 {
		t.Fatalf("re-issued while off: %d", n)
	}
	// Turned on: once for the first invitation only.
	h.invite(t)
	h.setSettings(t, func(p *passwordSettings) { p.InviteHours = 1; p.InviteAutoReissue = true })
	h.now = h.now.Add(2 * time.Hour)
	for range 3 {
		h.s.sweepInvites(ctx)
	}
	if n := len(h.mailsOf(t, mail.TemplateInvitation)); n != 3 {
		t.Fatalf("invitations %d, want 3 (two issued, one re-issued)", n)
	}
	if r := h.prov.last(provapi.OpTokenIssue); r.Actor.User != "lab.admin" {
		t.Fatalf("re-issued for %+v", r.Actor)
	}
	// The re-issued one, expired too, is not re-issued again.
	h.now = h.now.Add(2 * time.Hour)
	h.s.sweepInvites(ctx)
	if n := len(h.mailsOf(t, mail.TemplateInvitation)); n != 3 {
		t.Fatalf("re-issued twice: %d", n)
	}
	if !hasAction(h.auditActions(t), "invite.reissued:ok") {
		t.Fatal("re-issue not audited")
	}
}

func TestResetIsUniform(t *testing.T) {
	h := newPWHarness(t)
	// Off by default: no form, no link on the sign-in page.
	if r := h.browser().do("GET", "/reset", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("reset while off: %d", r.StatusCode)
	}
	if strings.Contains(body(t, h.browser().do("GET", "/signin", nil)), "signin-link-reset") {
		t.Fatal("reset link while off")
	}
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true })
	if !strings.Contains(body(t, h.browser().do("GET", "/signin", nil)), `data-e2e="signin-link-reset"`) {
		t.Fatal("no reset link")
	}
	page := body(t, h.browser().do("GET", "/reset", nil))
	mustTagE2E(t, page)
	var first string
	for i, typed := range []string{"nobody.here", "priv.user", "outside@example.org", "nomail.user", "NORMAL.USER", ""} {
		b := h.browser()
		b.ip = "198.51.100." + itoa(10+i)
		b.do("GET", "/reset", nil)
		r := b.do("POST", "/reset", url.Values{"identifier": {typed}})
		p := body(t, r)
		if r.StatusCode != http.StatusOK || !strings.Contains(p, `data-e2e="reset-text-sent"`) {
			t.Fatalf("%q: %d", typed, r.StatusCode)
		}
		if i == 0 {
			first = p
		} else if p != first {
			t.Errorf("%q: a different answer", typed)
		}
	}
	h.s.bgJobs.Wait()
	resets := h.mailsOf(t, mail.TemplateReset)
	if len(resets) != 1 || resets[0].To != "normal.user@example.org" {
		t.Fatalf("reset messages %s", jsonOf(resets))
	}
	audit := h.auditText(t)
	if strings.Contains(audit, "nobody.here") {
		t.Fatal("typed identifier stored in the audit log")
	}
	if !strings.Contains(audit, "id:"+identifierHash("nobody.here")) || !strings.Contains(audit, "privileged account") ||
		!strings.Contains(audit, "outside the provisioner's scope") || !strings.Contains(audit, "no address") {
		t.Fatalf("audit:\n%s", audit)
	}
	if identifierHash("Normal.User ") != identifierHash("normal.user") || len(identifierHash("x")) != 16 {
		t.Fatal("identifier hash")
	}
	acts := h.auditActions(t)
	if !hasAction(acts, "reset.requested:pending") || !hasAction(acts, "reset.mailed:ok") || !hasAction(acts, "reset.refused:denied") {
		t.Fatalf("audit %v", acts)
	}
}

func TestResetThrottles(t *testing.T) {
	h := newPWHarness(t)
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true })
	// Per client address: 5 per 15 minutes, then the same page and nothing.
	b := h.browser()
	b.do("GET", "/reset", nil)
	for range resetsPerAddress {
		b.do("POST", "/reset", url.Values{"identifier": {"nobody"}})
	}
	h.s.bgJobs.Wait()
	finds := h.prov.count(provapi.OpUserFind)
	r := b.do("POST", "/reset", url.Values{"identifier": {"normal.user"}})
	h.s.bgJobs.Wait()
	if r.StatusCode != http.StatusOK || !strings.Contains(body(t, r), "reset-text-sent") || h.prov.count(provapi.OpUserFind) != finds {
		t.Fatal("per-address limit")
	}
	// Per account: 3 per hour, silently.
	for i := range 5 {
		b := h.browser()
		b.ip = "203.0.113." + itoa(i+1)
		b.do("GET", "/reset", nil)
		b.do("POST", "/reset", url.Values{"identifier": {"normal.user@example.org"}})
	}
	h.s.bgJobs.Wait()
	if n := h.prov.count(provapi.OpTokenIssue); n != resetsPerAccountHour {
		t.Fatalf("tokens issued %d, want %d", n, resetsPerAccountHour)
	}
	if !strings.Contains(h.auditText(t), "per-account limit") {
		t.Fatal("account limit not audited")
	}
}

// resetLink requests a reset for normal.user and returns the link.
func (h *pwHarness) resetLink(t *testing.T) string {
	t.Helper()
	b := h.browser()
	b.ip = "203.0.113." + itoa(len(h.mails(t))+1)
	b.do("GET", "/reset", nil)
	b.do("POST", "/reset", url.Values{"identifier": {"normal.user"}})
	h.s.bgJobs.Wait()
	m := h.mailsOf(t, mail.TemplateReset)
	if len(m) == 0 {
		t.Fatal("no reset message")
	}
	return linkFrom(t, m[len(m)-1].Text)
}

func TestResetWithoutSecondFactor(t *testing.T) {
	h := newPWHarness(t)
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true })
	user := h.session(t, "normal.user", stageFull, false)
	link := h.resetLink(t)
	b := h.browser()
	if page := body(t, b.do("GET", link, nil)); !strings.Contains(page, "link-btn-start") {
		t.Fatal("reset link page")
	}
	if r := b.do("POST", link+"/start", nil); r.Header.Get("Location") != "/link/password" {
		t.Fatalf("start: %q", r.Header.Get("Location"))
	}
	r := b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	if r.Header.Get("Location") != "/link/done" || !h.prov.set[normalSID] || !h.prov.unlock[normalSID] {
		t.Fatalf("password: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	// Every session of the user ended.
	if h.s.sess.get(context.Background(), user) != nil {
		t.Fatal("session kept after the reset")
	}
	if n := h.mailsOf(t, mail.TemplatePasswordChanged); len(n) != 1 {
		t.Fatalf("notifications %d", len(n))
	}
	if !hasAction(h.auditActions(t), "reset.completed:ok") {
		t.Fatal("reset not audited")
	}
	// Unlock off: not asked.
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true; p.ResetUnlock = false })
	link = h.resetLink(t)
	b = h.browser()
	b.do("POST", link+"/start", nil)
	b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!2"}, "confirm": {"N3w-pass!2"}})
	if h.prov.unlock[normalSID] {
		t.Fatal("unlock asked while off")
	}
}

func TestResetSecondFactor(t *testing.T) {
	h := newPWHarness(t)
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true })
	secret := h.enrollTOTP(t, "normal.user")
	link := h.resetLink(t)
	b := h.browser()
	if r := b.do("POST", link+"/start", nil); r.Header.Get("Location") != "/link/2fa" {
		t.Fatalf("start: %q", r.Header.Get("Location"))
	}
	// The password step waits for the second factor.
	if r := b.do("POST", "/link/password", url.Values{"new": {"x"}, "confirm": {"x"}}); r.Header.Get("Location") != "/link/2fa" || h.prov.set[normalSID] {
		t.Fatal("password before the second factor")
	}
	mustTagE2E(t, body(t, b.do("GET", "/link/2fa", nil)))
	for i := range maxLinkMFAFailures - 1 {
		if r := b.do("POST", "/link/2fa", url.Values{"code": {"000000"}}); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: %d", i, r.StatusCode)
		}
	}
	r := b.do("POST", "/link/2fa", url.Values{"code": {"000000"}})
	if page := body(t, r); !strings.Contains(page, "link-text-invalid") {
		t.Fatal("token kept after 5 failures")
	}
	if rv := h.prov.last(provapi.OpTokenRevoke); rv == nil || !strings.Contains(string(rv.Params), "mfa-failed") {
		t.Fatalf("revoke %+v", rv)
	}
	if !hasAction(h.auditActions(t), "reset.revoked:ok") {
		t.Fatal("revocation not audited")
	}
	// A new link with the right code.
	h.s.mfaFails.Reset("normal.user")
	link = h.resetLink(t)
	b = h.browser()
	b.do("POST", link+"/start", nil)
	h.now = h.now.Add(totp.Period)
	r = b.do("POST", "/link/2fa", url.Values{"code": {totp.Code(secret, totp.Step(h.now))}})
	if r.Header.Get("Location") != "/link/password" {
		t.Fatalf("right code: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	r = b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	if r.Header.Get("Location") != "/link/done" {
		t.Fatalf("password: %q", r.Header.Get("Location"))
	}
	// A key assertion without a ceremony is refused like a wrong code.
	link = h.resetLink(t)
	b = h.browser()
	b.do("POST", link+"/start", nil)
	if r := b.do("POST", "/link/2fa/key", url.Values{"response": {"{}"}}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad assertion: %d", r.StatusCode)
	}
}

func TestResetPolicies(t *testing.T) {
	h := newPWHarness(t)
	ctx := context.Background()
	// Always: no second factor, no reset.
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true; p.ResetMFA = resetMFAAlways })
	b := h.browser()
	b.do("GET", "/reset", nil)
	b.do("POST", "/reset", url.Values{"identifier": {"normal.user"}})
	h.s.bgJobs.Wait()
	if len(h.mailsOf(t, mail.TemplateReset)) != 0 || !strings.Contains(h.auditText(t), "no second factor") {
		t.Fatal("reset without a second factor under always")
	}
	// The recovery address: not within 72 hours of a change, then yes.
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true })
	if err := h.st.SetRecoveryEmail(ctx, store.RecoveryEmail{UserSID: normalSID, Address: "alt@example.net", VerifiedAt: h.now, ChangedAt: h.now}); err != nil {
		t.Fatal(err)
	}
	h.resetLink(t)
	if m := h.mailsOf(t, mail.TemplateReset); len(m) != 1 {
		t.Fatalf("recent recovery address used: %d", len(m))
	}
	h.now = h.now.Add(73 * time.Hour)
	h.resetLink(t)
	var to []string
	for _, m := range h.mailsOf(t, mail.TemplateReset) {
		to = append(to, m.To)
	}
	if len(to) != 3 || to[1] != "normal.user@example.org" || to[2] != "alt@example.net" {
		t.Fatalf("recipients %v", to)
	}
	// A disabled account (not locked) is not reset.
	h.prov.users[normalSID].Enabled = false
	n := len(h.mailsOf(t, mail.TemplateReset))
	b = h.browser()
	b.ip = "203.0.113.200"
	b.do("GET", "/reset", nil)
	b.do("POST", "/reset", url.Values{"identifier": {"normal.user"}})
	h.s.bgJobs.Wait()
	if len(h.mailsOf(t, mail.TemplateReset)) != n || !strings.Contains(h.auditText(t), "account disabled") {
		t.Fatal("disabled account reset")
	}
	// A locked one is.
	h.prov.users[normalSID].Locked = true
	h.resetLink(t)
	// With a second factor removed after the link, the start refuses.
	h.setSettings(t, func(p *passwordSettings) { p.ResetEnabled = true; p.ResetMFA = resetMFAAlways })
	h.enrollTOTP(t, "normal.user")
	h.prov.users[normalSID].Enabled = true
	link := h.resetLink(t)
	if err := h.st.DeleteTOTP(ctx, normalSID); err != nil {
		t.Fatal(err)
	}
	if page := body(t, h.browser().do("POST", link+"/start", nil)); !strings.Contains(page, "link-text-invalid") {
		t.Fatal("reset started without the required second factor")
	}
}

func TestNotifications(t *testing.T) {
	h := newPWHarness(t)
	ctx := context.Background()
	if err := h.st.SetRecoveryEmail(ctx, store.RecoveryEmail{UserSID: normalSID, Address: "alt@example.net", VerifiedAt: h.now, ChangedAt: h.now}); err != nil {
		t.Fatal(err)
	}
	h.s.notifyPasswordChanged(ctx, pwChange{SID: normalSID, SAM: "normal.user", Mail: "normal.user@example.org", ByAdmin: true, From: "192.0.2.99"})
	m := h.mailsOf(t, mail.TemplatePasswordChanged)
	if len(m) != 2 || !strings.Contains(m[0].Text, "an administrator") || strings.Contains(m[0].Text, "192.0.2.99") || strings.Contains(m[0].Text, "http") {
		t.Fatalf("admin notification %s", jsonOf(m))
	}
	h.s.notifyPasswordChanged(ctx, pwChange{SID: normalSID, SAM: "normal.user", Mail: "normal.user@example.org", From: "192.0.2.99", Lang: "pt-BR"})
	m = h.mailsOf(t, mail.TemplatePasswordChanged)
	if len(m) != 4 || !strings.Contains(m[3].Text, "192.0.2.99") {
		t.Fatalf("self notification %s", jsonOf(m))
	}
	h.setSettings(t, func(p *passwordSettings) { p.NotifyChanged = false })
	h.s.notifyPasswordChanged(ctx, pwChange{SID: normalSID, SAM: "normal.user", Mail: "normal.user@example.org"})
	if len(h.mailsOf(t, mail.TemplatePasswordChanged)) != 4 {
		t.Fatal("notified while off")
	}
	// Mail off: nothing, no error.
	h.s.mailq = nil
	h.s.notifyPasswordChanged(ctx, pwChange{SID: normalSID, Mail: "normal.user@example.org"})
}

func TestPasswordSettingsPage(t *testing.T) {
	// Without mail or the provisioner: the page says what is missing.
	plain := newHarness(t)
	admin := plain.session(t, "lab.admin", stageFull, true)
	page := plain.do("GET", "/admin/settings/passwords", admin, nil).Body.String()
	for _, want := range []string{"passwords-text-missing-mail", "passwords-text-missing-provisioner", "passwords-text-missing-public-url", `data-e2e="nav-link-passwords"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	mustTagE2E(t, page)

	h := newPWHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin = h.session(t, "lab.admin", stageFull, true)
	page = h.do("GET", "/admin/settings/passwords", admin, nil).Body.String()
	if !strings.Contains(page, "svc-conductor-prov") || !strings.Contains(page, "OU=People,DC=lab,DC=test") || strings.Contains(page, "passwords-card-missing") {
		t.Fatalf("page:\n%s", page)
	}
	form := url.Values{"invite_hours": {"48"}, "reset_minutes": {"20"}, "reset_mfa": {"always"}, "reset_enabled": {"1"}, "reset_unlock": {"1"},
		"notify_password_changed": {"1"}}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("invite_hours", "500")
	if w := h.do("POST", "/admin/settings/passwords", admin, bad); w.Code != http.StatusBadRequest {
		t.Fatalf("out of range: %d", w.Code)
	}
	bad.Set("invite_hours", "48")
	bad.Set("reset_mfa", "never")
	if w := h.do("POST", "/admin/settings/passwords", admin, bad); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mfa: %d", w.Code)
	}
	// Unchanged: nothing to confirm.
	same := url.Values{"invite_hours": {"72"}, "reset_minutes": {"30"}, "reset_mfa": {"if-enrolled"}, "reset_unlock": {"1"}, "notify_password_changed": {"1"}}
	if w := h.do("POST", "/admin/settings/passwords", admin, same); w.Header().Get("Location") != "/admin/settings/passwords" {
		t.Fatalf("no change: %q", w.Header().Get("Location"))
	}
	w := h.do("POST", "/admin/settings/passwords", admin, form)
	loc := w.Header().Get("Location")
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "reset.enabled = false") || !strings.Contains(cp, "reset.enabled = true") || !strings.Contains(cp, "confirm-text-reauth") {
		t.Fatalf("preview:\n%s", cp)
	}
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("without a second factor: %d", w.Code)
	}
	if got := h.s.passwordSettings(context.Background()); got.ResetEnabled {
		t.Fatal("saved without re-authentication")
	}
	h.confirmWith(t, admin, loc, secret)
	got := h.s.passwordSettings(context.Background())
	if got.InviteHours != 48 || got.ResetMinutes != 20 || got.ResetMFA != resetMFAAlways || !got.ResetEnabled || got.InviteAutoReissue {
		t.Fatalf("saved %+v", got)
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "settings.update"}, 0, 10)
	var okEv *store.AuditEvent
	for i := range evs {
		if evs[i].Result == store.ResultOK {
			okEv = &evs[i]
		}
	}
	if okEv == nil || !strings.Contains(okEv.Detail, "before:") || !strings.Contains(okEv.Detail, "after:") || !strings.Contains(okEv.Detail, "invite.hours = 48") {
		t.Fatalf("audit %+v", evs)
	}
	// Bad stored values fall back to the defaults.
	if err := h.st.PutSettings(context.Background(), map[string]string{setInviteHours: "999"}, "x"); err != nil {
		t.Fatal(err)
	}
	if got := h.s.passwordSettings(context.Background()); got != defaultPasswordSettings() {
		t.Fatalf("out of range stored value kept: %+v", got)
	}
	if err := h.st.PutSettings(context.Background(), map[string]string{setInviteHours: "\"x\""}, "x"); err != nil {
		t.Fatal(err)
	}
	if got := h.s.passwordSettings(context.Background()); got.InviteHours != 72 {
		t.Fatalf("unreadable value: %+v", got)
	}
	// A provisioner that does not answer: said on the page.
	h.prov.fail[provapi.OpStatus] = &provapi.Error{Code: provapi.CodeUnavailable, Message: "down"}
	if page := h.do("GET", "/admin/settings/passwords", admin, nil).Body.String(); !strings.Contains(page, "passwords-text-prov-error") {
		t.Fatal("provisioner error not shown")
	}
}

func TestRecoveryAddress(t *testing.T) {
	h := newPWHarness(t)
	ctx := context.Background()
	user := h.session(t, "normal.user", stageFull, false)
	page := h.do("GET", "/me/recovery-email", user, nil).Body.String()
	if !strings.Contains(page, "recovery-text-none") || strings.Contains(page, "recovery-input-mfa") {
		t.Fatalf("page:\n%s", page)
	}
	mustTagE2E(t, page)
	if !strings.Contains(h.do("GET", "/me/security", user, nil).Body.String(), "security-link-recovery-email") {
		t.Fatal("no entry on the security page")
	}
	if w := h.do("POST", "/me/recovery-email", user, url.Values{"address": {"a@b\r\nBcc: c@d"}, "password": {"pw"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad address: %d", w.Code)
	}
	h.backend.results["normal.user"] = &ad.AuthError{Reason: ad.ReasonInvalidCredentials}
	if w := h.do("POST", "/me/recovery-email", user, url.Values{"address": {"alt@example.net"}, "password": {"wrong"}}); w.Code != http.StatusUnauthorized ||
		len(h.mailsOf(t, mail.TemplateAlternateVerify)) != 0 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	h.backend.results["normal.user"] = nil
	if w := h.do("POST", "/me/recovery-email", user, url.Values{"address": {"alt@example.net"}, "password": {"pw"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("set: %d", w.Code)
	}
	codes := h.mailsOf(t, mail.TemplateAlternateVerify)
	if len(codes) != 1 || codes[0].To != "alt@example.net" {
		t.Fatalf("code message %s", jsonOf(codes))
	}
	code := regexp.MustCompile(`\b\d{6}\b`).FindString(codes[0].Text)
	if !strings.Contains(h.do("GET", "/me/recovery-email", user, nil).Body.String(), "recovery-input-code") {
		t.Fatal("no verification form")
	}
	if w := h.do("POST", "/me/recovery-email/verify", user, url.Values{"code": {"000000"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", w.Code)
	}
	if w := h.do("POST", "/me/recovery-email/verify", user, url.Values{"code": {code}}); w.Code != http.StatusSeeOther {
		t.Fatalf("verify: %d", w.Code)
	}
	r, err := h.st.GetRecoveryEmail(ctx, normalSID)
	if err != nil || r.Address != "alt@example.net" {
		t.Fatalf("stored %+v %v", r, err)
	}
	page = h.do("GET", "/me/recovery-email", user, nil).Body.String()
	if !strings.Contains(page, "a***@example.net") || !strings.Contains(page, "recovery-text-blocked") {
		t.Fatalf("masked current:\n%s", page)
	}
	// Change: the previous address is told.
	h.do("POST", "/me/recovery-email", user, url.Values{"address": {"other@example.com"}, "password": {"pw"}})
	code = regexp.MustCompile(`\b\d{6}\b`).FindString(h.mailsOf(t, mail.TemplateAlternateVerify)[1].Text)
	h.do("POST", "/me/recovery-email/verify", user, url.Values{"code": {code}})
	if ch := h.mailsOf(t, mail.TemplateAlternateChanged); len(ch) != 1 || ch[0].To != "alt@example.net" {
		t.Fatalf("previous address not told: %s", jsonOf(ch))
	}
	// Five wrong codes end the verification.
	h.do("POST", "/me/recovery-email", user, url.Values{"address": {"third@example.com"}, "password": {"pw"}})
	for range recoveryCodeTries {
		h.do("POST", "/me/recovery-email/verify", user, url.Values{"code": {"111111"}})
	}
	if w := h.do("POST", "/me/recovery-email/verify", user, url.Values{"code": {"222222"}}); !strings.Contains(w.Body.String(), "expired or was mistyped") {
		t.Fatal("verification not ended")
	}
	// The verification codes are limited per user.
	for range recoveryCodesPerHour {
		h.do("POST", "/me/recovery-email", user, url.Values{"address": {"x@example.com"}, "password": {"pw"}})
	}
	if w := h.do("POST", "/me/recovery-email", user, url.Values{"address": {"x@example.com"}, "password": {"pw"}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("code limit: %d", w.Code)
	}
	// Removal: the address is told.
	if w := h.do("POST", "/me/recovery-email/remove", user, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", w.Code)
	}
	if _, err := h.st.GetRecoveryEmail(ctx, normalSID); err == nil || len(h.mailsOf(t, mail.TemplateAlternateChanged)) != 2 {
		t.Fatal("not removed or not told")
	}
	acts := h.auditActions(t)
	for _, want := range []string{"self.recovery_email_set:ok", "self.recovery_email_set:denied", "self.recovery_email_removed:ok"} {
		if !hasAction(acts, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	// With a second factor, the code is required too.
	h.enrollTOTP(t, "normal.user")
	if !strings.Contains(h.do("GET", "/me/recovery-email", user, nil).Body.String(), "recovery-input-mfa") {
		t.Fatal("no second-factor field")
	}
	if w := h.do("POST", "/me/recovery-email", user, url.Values{"address": {"y@example.com"}, "password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("without the second factor: %d", w.Code)
	}
	if maskAddress("x") != "***" || maskAddress("ana@example.org") != "a***@example.org" {
		t.Fatal("mask")
	}
}

func TestRecoveryAddressNeedsMail(t *testing.T) {
	h := newHarness(t)
	user := h.session(t, "normal.user", stageFull, false)
	if page := h.do("GET", "/me/recovery-email", user, nil).Body.String(); !strings.Contains(page, "recovery-card-off") {
		t.Fatal("no notice without mail")
	}
	if w := h.do("POST", "/me/recovery-email", user, url.Values{"address": {"a@example.org"}, "password": {"pw"}}); w.Code != http.StatusConflict {
		t.Fatalf("set without mail: %d", w.Code)
	}
	if strings.Contains(h.do("GET", "/me/security", user, nil).Body.String(), "security-link-recovery-email") {
		t.Fatal("entry without mail")
	}
}

func TestProvErrorMapping(t *testing.T) {
	cases := map[error]string{
		errProvisionerOff: "prov.err.off",
		&provapi.Error{Code: provapi.CodeOutOfScope}:    "prov.err.out_of_scope",
		&provapi.Error{Code: provapi.CodeRateLimited}:   "prov.err.rate_limited",
		&provapi.Error{Code: provapi.CodeNotFound}:      "prov.err.not_found",
		&provapi.Error{Code: provapi.CodeUnavailable}:   "prov.err.unavailable",
		&provapi.Error{Code: provapi.CodeInvalidParams}: "prov.err.invalid",
		&provapi.Error{Code: provapi.CodeDirectory}:     "prov.err.failed",
		context.DeadlineExceeded:                        "prov.err.unavailable",
	}
	for err, want := range cases {
		if got := provErrKey(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	if provCode(errProvisionerOff) != "off" || provCode(context.Canceled) != "error" || provCode(&provapi.Error{Code: provapi.CodeStale}) != "stale" {
		t.Fatal("provCode")
	}
	h := newHarness(t)
	for err, want := range map[error]string{errMailOff: "invite.err.off", errNoPublicURL: "invite.err.off", errNoAddress: "invite.reason.no_mail"} {
		if got := h.s.adErrorKey(err); got != want {
			t.Errorf("%v: %s", err, got)
		}
	}
	if recipients("a@example.org", "A@Example.org", "", "bad", "b@example.org") == nil ||
		len(recipients("a@example.org", "A@Example.org", "", "bad", "b@example.org")) != 2 {
		t.Fatal("recipients")
	}
}

func TestLinkStoreBounds(t *testing.T) {
	var m linkStore
	m.byHash = map[string]*linkRecord{}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for i := range 3 {
		m.put(&linkRecord{hash: hashToken("c" + itoa(i)), expires: now.Add(time.Duration(i) * time.Minute)})
	}
	if m.get("c1", now) == nil || m.get("", now) != nil || m.get(strings.Repeat("x", 200), now) != nil {
		t.Fatal("get")
	}
	if m.get("c0", now.Add(time.Second)) != nil {
		t.Fatal("expired record returned")
	}
	m.sweep(now.Add(90 * time.Second))
	if len(m.byHash) != 1 {
		t.Fatalf("sweep left %d", len(m.byHash))
	}
}

func TestInviteAndRevokeOperations(t *testing.T) {
	h := newPWHarness(t)
	ctx := context.Background()
	rc := h.adminRC(t)
	w := httptest.NewRecorder()
	rc.w = w
	u := ad.User{DN: "CN=new.person,OU=People,DC=lab,DC=test", SAMAccountName: "new.person", SID: sid.MustParse(inviteeSID)}
	p := h.s.inviteOp(ctx, rc, u)
	if p == nil || p.action != "invite.issued" || !strings.Contains(p.summary, "new.person@example.org") || !strings.Contains(p.preview, "valid 72 hours") {
		t.Fatalf("op %+v", p)
	}
	if err := p.run(ctx, rc); err != nil || len(h.mailsOf(t, mail.TemplateInvitation)) != 1 {
		t.Fatalf("run: %v", err)
	}
	// Refused accounts: the reason, audited, nothing proposed.
	for _, s := range []string{privSID, outsideSID, nomailSID} {
		rc.w = httptest.NewRecorder()
		if p := h.s.inviteOp(ctx, rc, ad.User{DN: "CN=x", SAMAccountName: "x", SID: sid.MustParse(s)}); p != nil {
			t.Errorf("%s: proposed", s)
		}
	}
	h.prov.fail[provapi.OpUserCheck] = &provapi.Error{Code: provapi.CodeUnavailable, Message: "down"}
	rc.w = httptest.NewRecorder()
	if p := h.s.inviteOp(ctx, rc, u); p != nil {
		t.Fatal("proposed while the provisioner is down")
	}
	delete(h.prov.fail, provapi.OpUserCheck)
	acts := h.auditActions(t)
	if !hasAction(acts, "invite.refused:denied") || !hasAction(acts, "invite.refused:failed") {
		t.Fatalf("refusals %v", acts)
	}
	// Revoke the open invitation.
	r := h.s.revokeOp(rc, u, provapi.PurposeInvite)
	if r.action != "invite.revoked" {
		t.Fatalf("revoke op %+v", r)
	}
	if err := r.run(ctx, rc); err != nil || !strings.Contains(r.preview, "# revoked: 1") {
		t.Fatalf("revoke: %v %q", err, r.preview)
	}
	h.prov.fail[provapi.OpTokenRevoke] = &provapi.Error{Code: provapi.CodeInternal, Message: "x"}
	if err := r.run(ctx, rc); err == nil {
		t.Fatal("revoke error lost")
	}
	// The invitation of an account just created.
	h.s.sidOfUser = func(context.Context, *reqCtx, string) (string, error) { return inviteeSID, nil }
	if err := h.s.inviteAfterCreate("new.person", "new.person@example.org", u.DN, 72)(ctx, rc); err != nil {
		t.Fatal(err)
	}
	h.s.sidOfUser = func(context.Context, *reqCtx, string) (string, error) { return "", ad.ErrNotFound }
	if err := h.s.inviteAfterCreate("new.person", "new.person@example.org", u.DN, 72)(ctx, rc); err == nil {
		t.Fatal("lookup error lost")
	}
	evs, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "invite.issued"}, 0, 10)
	if len(evs) != 2 || evs[0].Result == evs[1].Result {
		t.Fatalf("audit %+v", evs)
	}
	// The routes refuse before LDAP when invitations are off.
	h.s.prov = nil
	admin := h.session(t, "lab.admin", stageFull, true)
	if w := h.do("POST", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/invite", admin, nil); w.Code != http.StatusConflict {
		t.Fatalf("invite while off: %d", w.Code)
	}
	if w := h.do("POST", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/tokens/revoke", admin, url.Values{"purpose": {"invite"}}); w.Code != http.StatusConflict {
		t.Fatalf("revoke while off: %d", w.Code)
	}
	if w := h.do("POST", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/tokens/revoke", admin, url.Values{"purpose": {"other"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad purpose: %d", w.Code)
	}
}

func TestLinkTemporaryFailures(t *testing.T) {
	h := newPWHarness(t, func(c *config.Config) { c.MFA.Policy = config.MFARequired })
	link := h.invite(t)
	b := h.browser()
	b.do("GET", link, nil)
	b.do("POST", link+"/start", nil)
	// Pages of later steps go back to the current one.
	for _, p := range []string{"/link/enroll", "/link/2fa"} {
		if r := b.do("GET", p, nil); r.Header.Get("Location") != "/link/password" {
			t.Errorf("%s: %q", p, r.Header.Get("Location"))
		}
	}
	if r := b.do("GET", "/link/enroll/qr.png", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("QR before the step: %d", r.StatusCode)
	}
	for code, want := range map[provapi.ErrorCode]string{provapi.CodeRateLimited: "Too many requests", provapi.CodeDirectory: "cannot be completed"} {
		h.prov.fail[provapi.OpPasswordSet] = &provapi.Error{Code: code, Message: "x"}
		r := b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
		if r.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body(t, r), want) {
			t.Errorf("%s: %d", code, r.StatusCode)
		}
	}
	delete(h.prov.fail, provapi.OpPasswordSet)
	if r := b.do("POST", "/link/password", url.Values{"new": {""}, "confirm": {""}}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty: %d", r.StatusCode)
	}
	if r := b.do("POST", "/link/password", url.Values{"new": {strings.Repeat("x", 1100)}, "confirm": {strings.Repeat("x", 1100)}}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("too long: %d", r.StatusCode)
	}
	if r := b.do("GET", "/link/password", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("password page: %d", r.StatusCode)
	}
	b.do("POST", "/link/password", url.Values{"new": {"N3w-pass!"}, "confirm": {"N3w-pass!"}})
	if r := b.do("GET", "/link/password", nil); r.Header.Get("Location") != "/link/enroll" {
		t.Fatalf("password page after the step: %q", r.Header.Get("Location"))
	}
	// Security keys: a bad name, then a registration WebAuthn refuses.
	if r := b.do("POST", "/link/enroll/key", url.Values{"name": {""}}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("key name: %d", r.StatusCode)
	}
	if r := b.do("POST", "/link/enroll/key", url.Values{"name": {"key"}, "response": {"{}"}}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("key registration: %d", r.StatusCode)
	}
	// The token is revoked meanwhile: the flow ends on the neutral page.
	h.prov.mu.Lock()
	for _, tk := range h.prov.tokens {
		tk.state = provapi.StateRevoked
	}
	h.prov.mu.Unlock()
	rec := h.s.links.get(b.cookies[linkCookie], h.now)
	code := totp.Code(rec.sess.enrollSecret, totp.Step(h.now))
	if page := body(t, b.do("POST", "/link/enroll", url.Values{"code": {code}})); !strings.Contains(page, "link-text-invalid") {
		t.Fatal("revoked token completed")
	}
	if b.cookies[linkCookie] != "" {
		t.Fatal("link cookie kept")
	}
}

func TestLinkStoreEvicts(t *testing.T) {
	var m linkStore
	m.byHash = map[string]*linkRecord{}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for i := range maxLinkRecords + 1 {
		m.put(&linkRecord{hash: "h" + itoa(i), expires: now.Add(time.Duration(i) * time.Second)})
	}
	if len(m.byHash) != maxLinkRecords || m.byHash["h0"] != nil {
		t.Fatalf("eviction: %d", len(m.byHash))
	}
}
