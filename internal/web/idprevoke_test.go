package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// TestIdPRevokeAfterFactorChange: a 2FA change in conductor ends the
// account's sessions at conductor-idp; a failed call is audited and shown.
func TestIdPRevokeAfterFactorChange(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "normal.user")
	tok := h.session(t, "normal.user", stageFull, true)
	h.now = h.now.Add(totp.Period)
	h.do("POST", "/me/2fa/recovery-codes", tok, url.Values{"code": {totp.Code(secret, totp.Step(h.now))}})
	req := fi.last(idpapi.OpUserRevoke)
	if req == nil {
		t.Fatal("no revocation after new recovery codes")
	}
	var p idpapi.UserRevokeParams
	_ = json.Unmarshal(req.Params, &p)
	if p.User != "normal.user" || !strings.Contains(p.Reason, "recovery codes") || req.Actor.User != "normal.user" {
		t.Fatalf("revocation %+v by %+v", p, req.Actor)
	}
	if e := lastAudit(t, h.st, "sso.user_revoke"); e.Result != store.ResultOK || e.Target != "normal.user" {
		t.Fatalf("audit %+v", e)
	}
	// conductor-idp unreachable: the change stands, the failure is audited
	// and shown.
	fi.fail[idpapi.OpUserRevoke] = &idpapi.Error{Code: idpapi.CodeUnavailable, Message: "down"}
	h.now = h.now.Add(totp.Period)
	h.do("POST", "/me/2fa/recovery-codes", tok, url.Values{"code": {totp.Code(secret, totp.Step(h.now))}})
	if e := lastAudit(t, h.st, "sso.user_revoke"); e.Result != store.ResultFailed {
		t.Fatalf("failed revocation audited as %+v", e)
	}
	if e := lastAudit(t, h.st, "mfa.recovery_codes"); e.Result != store.ResultOK {
		t.Fatalf("the change itself: %+v", e)
	}
	page := h.do("GET", "/me/security", tok, nil).Body.String()
	if !strings.Contains(page, "could not end the single sign-on sessions") {
		t.Fatal("failed revocation not shown")
	}
}

// TestIdPRevokeHelper: without [idp] nothing is called; a failure maps to
// its message (used by the confirmation's follow-up and bulk rows).
func TestIdPRevokeHelper(t *testing.T) {
	h := newHarness(t)
	if err := h.s.revokeIdPUser(context.Background(), nil, "normal.user", "test"); err != nil {
		t.Fatalf("without [idp]: %v", err)
	}
	h2, fi := ssoHarness(t)
	fi.fail[idpapi.OpUserRevoke] = &idpapi.Error{Code: idpapi.CodeFailed, Message: "x"}
	err := h2.s.revokeIdPUser(context.Background(), nil, "normal.user", "password reset by an administrator")
	var re *errIDPRevoke
	if !errors.As(err, &re) {
		t.Fatalf("error %v", err)
	}
	msg := h2.s.errMessage(func(k string, a ...any) string { return h2.s.cat.T("en", k, a...) }, err)
	if !strings.Contains(msg, "normal.user") || !strings.Contains(msg, "single sign-on") {
		t.Fatalf("message %q", msg)
	}
	if req := fi.last(idpapi.OpUserRevoke); req == nil || req.Actor.SID != "S-1-5-18" {
		t.Fatalf("system actor: %+v", req)
	}
}

// TestSSOClientEmailVerified: the client form carries email_verified.
func TestSSOClientEmailVerified(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if body := h.do("GET", "/admin/sso/oidc/new", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-check-email-verified"`) ||
		strings.Contains(body, `name="email_verified" type="checkbox" value="1" checked`) {
		t.Fatal("email_verified box missing or ticked by default")
	}
	form := url.Values{"name": {"App"}, "kind": {"confidential"}, "redirect_uris": {"https://app.lab.test/cb"},
		"scopes": {"email"}, "allow_all": {"1"}, "email_verified": {"1"}, "action": {"review"}}
	loc := h.do("POST", "/admin/sso/oidc/form", admin, form).Header().Get("Location")
	if cp := h.do("GET", loc, admin, nil).Body.String(); !strings.Contains(cp, "email_verified: true") {
		t.Fatal("preview lacks email_verified")
	}
	h.confirmWith(t, admin, loc, secret)
	var p idpapi.ClientCreateParams
	_ = json.Unmarshal(fi.last(idpapi.OpClientCreate).Params, &p)
	if !p.Input.EmailVerified {
		t.Fatalf("create params %+v", p.Input)
	}
}
