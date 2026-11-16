package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// TestEnrolledKeysCountWithWebAuthnOff: a user who enrolled only a security
// key keeps a second factor when an operator turns WebAuthn off: the
// sign-in, the password reset links and conductor-idp still ask for one
// (a recovery code then), instead of letting the password alone through.
func TestEnrolledKeysCountWithWebAuthnOff(t *testing.T) {
	h := newHarness(t) // no [webauthn]
	ctx := context.Background()
	u, _ := sid.MustParse(testDomain).WithRID(userRIDs["normal.user"])
	if err := h.st.AddWebAuthnCredential(ctx, store.WebAuthnCredential{ID: "k1", UserSID: u.String(), Username: "normal.user",
		Name: "Key", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	codes, err := h.s.ensureRecoveryCodes(ctx, u.String())
	if err != nil || len(codes) == 0 {
		t.Fatalf("recovery codes: %v", err)
	}
	if !h.s.hasSecondFactor(ctx, u.String()) {
		t.Fatal("enrolled key ignored by hasSecondFactor")
	}
	w := h.signin(t, "normal.user", "pw", "")
	if w.Header().Get("Location") != "/signin/2fa" {
		t.Fatalf("sign-in skipped the second factor: %q", w.Header().Get("Location"))
	}
	tok := sessionFrom(w)
	if page := h.do("GET", "/signin/2fa", tok, nil).Body.String(); !strings.Contains(page, "mfa-text-keys-off") {
		t.Fatal("the 2FA page does not say that keys are off")
	}
	if w := h.do("GET", "/me", tok, nil); w.Header().Get("Location") != "/signin/2fa" {
		t.Fatalf("reached /me without a second factor: %d", w.Code)
	}
	if w := h.do("POST", "/signin/2fa", tok, url.Values{"code": {codes[0]}}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/me" {
		t.Fatalf("recovery code: %d %q", w.Code, w.Header().Get("Location"))
	}
	a := h.s.answerMFA(ctx, mfaReq(idpapi.MFAOpStatus, "normal.user", testDomain+"-513"))
	if !a.Enrolled || a.Keys != 0 || a.TOTP {
		t.Fatalf("conductor-idp status: %+v", a)
	}
}
