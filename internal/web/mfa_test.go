package web

import (
	"context"
	"encoding/base32"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/samba-conductor/conductor/internal/totp"
)

var secretRE = regexp.MustCompile(`data-e2e="enroll-text-secret">([A-Z2-7]+)<`)
var codeRE = regexp.MustCompile(`data-e2e="recovery-text-code">([a-z0-9-]+)<`)

func decodeSecret(t *testing.T, b32 string) []byte {
	t.Helper()
	for _, try := range []string{b32, b32 + "===="} {
		if s, err := b32dec(try); err == nil {
			return s
		}
	}
	t.Fatalf("secret %q", b32)
	return nil
}

func TestAdminEnrollmentLinkAndTOTP(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tok, hash := NewEnrollLinkToken()
	if err := h.st.CreateEnrollLink(ctx, hash, "lab.admin", "test", enrollLinkTTL); err != nil {
		t.Fatal(err)
	}
	// A link issued for someone else does not help.
	other, otherHash := NewEnrollLinkToken()
	_ = h.st.CreateEnrollLink(ctx, otherHash, "helpdesk.user", "test", enrollLinkTTL)
	if w := h.signin(t, "lab.admin", "pw", other); w.Code != http.StatusForbidden {
		t.Fatalf("someone else's link: %d", w.Code)
	}
	w := h.signin(t, "lab.admin", "pw", tok)
	if w.Header().Get("Location") != "/signin/enroll" {
		t.Fatalf("admin with link: %d %q", w.Code, w.Header().Get("Location"))
	}
	sess := sessionFrom(w)
	// Nothing else is reachable before enrolling.
	if w := h.do("GET", "/admin", sess, nil); w.Header().Get("Location") != "/signin/enroll" {
		t.Fatalf("admin page before enrollment: %d %q", w.Code, w.Header().Get("Location"))
	}
	page := h.do("GET", "/signin/enroll", sess, nil)
	m := secretRE.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("no secret on the enrollment page")
	}
	secret := decodeSecret(t, m[1])
	if qr := h.do("GET", "/signin/enroll/qr.png", sess, nil); !isPNG(qr.Body.Bytes()) {
		t.Fatal("QR is not a PNG")
	}
	// Wrong code first.
	if w := h.do("POST", "/signin/enroll", sess, url.Values{"code": {"000000"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong first code: %d", w.Code)
	}
	code := totp.Code(secret, totp.Step(h.now))
	w = h.do("POST", "/signin/enroll", sess, url.Values{"code": {code}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/me/recovery-codes" {
		t.Fatalf("enroll: %d %q", w.Code, w.Header().Get("Location"))
	}
	// The cookie value was rotated: the pre-2FA value is dead.
	if h.s.sess.get(ctx, sess) != nil {
		t.Fatal("session id not rotated after enrollment")
	}
	full := sessionFrom(w)
	codesPage := h.do("GET", "/me/recovery-codes", full, nil)
	codes := codeRE.FindAllStringSubmatch(codesPage.Body.String(), -1)
	if len(codes) != totp.RecoveryCodeCount {
		t.Fatalf("recovery codes shown: %d", len(codes))
	}
	if again := h.do("GET", "/me/recovery-codes", full, nil); again.Code != http.StatusSeeOther {
		t.Fatal("recovery codes shown twice")
	}
	if w := h.do("GET", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/reset-password", full, nil); w.Code == http.StatusSeeOther || w.Code == http.StatusForbidden {
		t.Fatalf("admin page after enrollment: %d", w.Code)
	}
	// The link was single-use.
	if ok, _ := h.st.ValidEnrollLink(ctx, hash, "lab.admin"); ok {
		t.Fatal("enrollment link still valid")
	}

	// Next sign-in asks for a code; the enrollment code cannot be replayed.
	w = h.signin(t, "lab.admin", "pw", "")
	if w.Header().Get("Location") != "/signin/2fa" {
		t.Fatalf("second sign-in: %q", w.Header().Get("Location"))
	}
	mfaSess := sessionFrom(w)
	if w := h.do("POST", "/signin/2fa", mfaSess, url.Values{"code": {code}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code accepted: %d", w.Code)
	}
	h.now = h.now.Add(totp.Period)
	w = h.do("POST", "/signin/2fa", mfaSess, url.Values{"code": {totp.Code(secret, totp.Step(h.now))}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin" {
		t.Fatalf("2FA: %d %q", w.Code, w.Header().Get("Location"))
	}

	// A recovery code works once.
	w = h.signin(t, "lab.admin", "pw", "")
	s2 := sessionFrom(w)
	w = h.do("POST", "/signin/2fa", s2, url.Values{"code": {codes[0][1]}})
	if w.Header().Get("Location") != "/admin" {
		t.Fatalf("recovery code: %d", w.Code)
	}
	w = h.signin(t, "lab.admin", "pw", "")
	s3 := sessionFrom(w)
	if w := h.do("POST", "/signin/2fa", s3, url.Values{"code": {codes[0][1]}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("recovery code reused: %d", w.Code)
	}
	// Five wrong codes end the sign-in.
	for range 5 {
		h.do("POST", "/signin/2fa", s3, url.Values{"code": {"123456"}})
	}
	if h.s.sess.get(ctx, s3) != nil {
		t.Fatal("sign-in survived repeated wrong codes")
	}
}

func TestSessionTimeoutsAndSignoutEverywhere(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tok := h.session(t, "normal.user", stageFull, false)
	h.now = h.now.Add(14 * time.Minute)
	if h.s.sess.get(ctx, tok) == nil {
		t.Fatal("session ended before the idle timeout")
	}
	h.now = h.now.Add(16 * time.Minute)
	if h.s.sess.get(ctx, tok) != nil {
		t.Fatal("idle session still valid")
	}
	// Absolute timeout, even when active.
	tok = h.session(t, "normal.user", stageFull, false)
	for range 33 {
		h.now = h.now.Add(15 * time.Minute)
		if h.s.sess.get(ctx, tok) == nil {
			break
		}
	}
	if h.s.sess.get(ctx, tok) != nil {
		t.Fatal("session outlived the absolute timeout")
	}
	a := h.session(t, "normal.user", stageFull, false)
	b := h.session(t, "normal.user", stageFull, false)
	c := h.session(t, "auditor.user", stageFull, true)
	w := h.do("POST", "/me/sessions/signout-all", a, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("sign out everywhere: %d", w.Code)
	}
	if h.s.sess.get(ctx, a) != nil || h.s.sess.get(ctx, b) != nil || h.s.sess.get(ctx, c) == nil {
		t.Fatal("sign out everywhere ended the wrong sessions")
	}
}

func TestI18nKeysExist(t *testing.T) {
	h := newHarness(t)
	keyRE := regexp.MustCompile(`(?:\{\{|\()t "([a-zA-Z0-9_.]+)"`)
	names, _ := templateFS.ReadDir("templates")
	for _, n := range names {
		b, _ := templateFS.ReadFile("templates/" + n.Name())
		for _, m := range keyRE.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasSuffix(m[1], ".") && !h.s.cat.Has(m[1]) {
				t.Errorf("%s: missing message %q", n.Name(), m[1])
			}
		}
	}
	// Dynamic keys.
	for _, k := range []string{"role.admin", "role.helpdesk", "role.auditor", "groups.scope.global", "groups.scope.domainlocal",
		"groups.scope.universal", "groups.scope.builtin", "kind.user", "kind.group", "kind.computer", "kind.other",
		"mfa.policy.off", "mfa.policy.optional", "mfa.policy.required", "dashboard.stat.users", "dashboard.stat.users_disabled",
		"dashboard.stat.groups", "dashboard.stat.computers", "dashboard.stat.ous", "dashboard.stat.users_locked"} {
		if !h.s.cat.Has(k) {
			t.Errorf("missing dynamic message %q", k)
		}
	}
	for _, f := range adminFields {
		if !h.s.cat.Has(f.Label) {
			t.Errorf("missing field label %q", f.Label)
		}
	}
	for _, k := range signinMessages {
		if !h.s.cat.Has(k) {
			t.Errorf("missing sign-in message %q", k)
		}
	}
	// Every page renders in both languages without an unknown-key marker.
	tok := h.session(t, "normal.user", stageFull, false)
	for _, lang := range []string{"en", "pt-BR"} {
		for _, p := range []string{"/signin", "/me/password", "/me/security"} {
			w := h.do("GET", p+"?lang="+lang, tok, nil)
			if strings.Contains(w.Body.String(), "[") && regexp.MustCompile(`\[[a-z_]+\.[a-z_.]+\]`).MatchString(w.Body.String()) {
				t.Errorf("%s %s: untranslated key in page", lang, p)
			}
		}
	}
}

func b32dec(s string) ([]byte, error) {
	return b32NoPad.DecodeString(strings.TrimRight(s, "="))
}

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)
