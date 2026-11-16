package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

func lastAudit(t *testing.T, st *store.Store, action string) store.AuditEvent {
	t.Helper()
	evs, _, err := st.ListAudit(context.Background(), store.AuditFilter{Action: action}, 0, 1)
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s audit: %v", action, err)
	}
	return evs[0]
}

// enrollTOTP enrolls TOTP from self-service and returns the secret.
func enrollTOTP(t *testing.T, h *harness, tok string) []byte {
	t.Helper()
	page := h.do("GET", "/me/2fa/enroll", tok, nil)
	m := secretRE.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no secret on the enrollment page (%d %q)", page.Code, page.Header().Get("Location"))
	}
	secret := decodeSecret(t, m[1])
	w := h.do("POST", "/me/2fa/enroll", tok, url.Values{"code": {totp.Code(secret, totp.Step(h.now))}})
	if w.Header().Get("Location") != "/me/recovery-codes" {
		t.Fatalf("enroll: %d %q", w.Code, w.Header().Get("Location"))
	}
	return secret
}

// TestStepUpBeforeAddingFactor: adding TOTP or a security key needs a
// recent proof of the account (the password, plus a current factor once
// the user has one), and every added factor is announced by e-mail.
func TestStepUpBeforeAddingFactor(t *testing.T) {
	h := newPWHarness(t, withWebAuthn)
	ctx := context.Background()
	u, _ := sid.MustParse(testDomain).WithRID(userRIDs["normal.user"])
	if err := h.st.SetRecoveryEmail(ctx, store.RecoveryEmail{UserSID: u.String(), Address: "normal@example.net", VerifiedAt: h.now, ChangedAt: h.now}); err != nil {
		t.Fatal(err)
	}
	w := h.signin(t, "normal.user", "pw", "")
	tok := sessionFrom(w)

	// Right after the sign-in the password is fresh: enrollment opens.
	if w := h.do("GET", "/me/2fa/enroll", tok, nil); w.Code != http.StatusOK {
		t.Fatalf("fresh enroll page: %d", w.Code)
	}
	// Later, a session cookie alone is not enough.
	h.now = h.now.Add(stepUpWindow + time.Minute)
	if w := h.do("GET", "/me/2fa/enroll", tok, nil); w.Header().Get("Location") != "/me/security/verify" {
		t.Fatalf("stale enroll page: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := h.do("POST", "/me/2fa/keys/register", tok, url.Values{"name": {"thief"}, "response": {"{}"}}); w.Header().Get("Location") != "/me/security/verify" {
		t.Fatalf("stale key registration: %d %q", w.Code, w.Header().Get("Location"))
	}
	if e := lastAudit(t, h.st, "mfa.key_register"); e.Detail != "step-up required" || e.Result != store.ResultDenied {
		t.Fatalf("refusal audited as %+v", e)
	}
	sec := h.do("GET", "/me/security", tok, nil).Body.String()
	if !strings.Contains(sec, "security-link-stepup") || strings.Contains(sec, "/me/2fa/keys/register") {
		t.Fatal("security page offers a key registration without a step-up")
	}
	// The step-up of a user without a factor is the password.
	page := h.do("GET", "/me/security/verify", tok, nil).Body.String()
	if !strings.Contains(page, "stepup-input-password") || strings.Contains(page, "confirm-input-code") {
		t.Fatal("step-up page of a user without a factor")
	}
	h.backend.results["normal.user"] = &ad.AuthError{Reason: ad.ReasonInvalidCredentials, Mechanism: "kerberos"}
	if w := h.do("POST", "/me/security/verify", tok, url.Values{"password": {"wrong"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password step-up: %d", w.Code)
	}
	h.backend.results["normal.user"] = nil
	if w := h.do("POST", "/me/security/verify", tok, url.Values{"password": {"pw"}}); w.Header().Get("Location") != "/me/security" {
		t.Fatalf("step-up: %d %q", w.Code, w.Header().Get("Location"))
	}
	secret := enrollTOTP(t, h.harness, tok)
	if m := h.mailsOf(t, mail.TemplateFactorAdded); len(m) != 1 || m[0].To != "normal@example.net" || !strings.Contains(m[0].Text, "normal.user") {
		t.Fatalf("factor notice: %+v", m)
	}

	// With TOTP enrolled, the step-up needs the password and a code.
	h.now = h.now.Add(stepUpWindow + time.Minute)
	if w := h.do("POST", "/me/2fa/keys/register", tok, url.Values{"name": {"thief"}, "response": {"{}"}}); w.Header().Get("Location") != "/me/security/verify" {
		t.Fatalf("stale key registration with TOTP: %d %q", w.Code, w.Header().Get("Location"))
	}
	if page := h.do("GET", "/me/security/verify", tok, nil).Body.String(); !strings.Contains(page, "confirm-input-code") {
		t.Fatal("step-up page without the code field")
	}
	if w := h.do("POST", "/me/security/verify", tok, url.Values{"password": {"pw"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("step-up without a code: %d", w.Code)
	}
	if w := h.do("POST", "/me/security/verify", tok, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}}); w.Header().Get("Location") != "/me/security" {
		t.Fatalf("step-up with a code: %d %q", w.Code, w.Header().Get("Location"))
	}
	// Now the registration itself runs (and fails on the bogus response).
	h.do("POST", "/me/2fa/keys/register", tok, url.Values{"name": {"mine"}, "response": {"{}"}})
	if e := lastAudit(t, h.st, "mfa.key_register"); e.Detail != "refused" {
		t.Fatalf("registration after the step-up: %+v", e)
	}
	if e := lastAudit(t, h.st, "mfa.step_up"); e.Result != store.ResultOK {
		t.Fatalf("step-up audit %+v", e)
	}
}

// TestNewRecoveryCodesLimited: the recovery-code form is no TOTP oracle.
func TestNewRecoveryCodesLimited(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tok := sessionFrom(h.signin(t, "normal.user", "pw", ""))
	secret := enrollTOTP(t, h, tok)
	for i := range maxMFAFailures {
		w := h.do("POST", "/me/2fa/recovery-codes", tok, url.Values{"code": {"000000"}})
		if i < maxMFAFailures-1 && w.Header().Get("Location") != "/me/security" {
			t.Fatalf("wrong code %d: %d %q", i, w.Code, w.Header().Get("Location"))
		}
	}
	if h.s.sess.get(ctx, tok) != nil {
		t.Fatal("session survived repeated wrong codes")
	}
	// The account stays blocked for a new session too, even with a right code.
	tok2 := h.session(t, "normal.user", stageFull, true)
	h.do("POST", "/me/2fa/recovery-codes", tok2, url.Values{"code": {totp.Code(secret, totp.Step(h.now))}})
	if e := lastAudit(t, h.st, "mfa.recovery_codes"); e.Detail != "rate limited" {
		t.Fatalf("blocked account: %+v", e)
	}
	if h.s.sess.get(ctx, tok2) != nil {
		t.Fatal("blocked account kept its session")
	}
}
