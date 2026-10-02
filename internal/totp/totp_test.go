package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890" (8-digit codes
// there; the last 6 digits are the 6-digit codes).
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		if got := Code(secret, Step(time.Unix(ts, 0))); got != want {
			t.Errorf("t=%d: %s, want %s", ts, got, want)
		}
	}
}

func TestVerifyWindow(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code := Code(secret, Step(now.Add(d)))
		step, ok := Verify(secret, code, now)
		if !ok || step != Step(now.Add(d)) {
			t.Errorf("offset %v rejected", d)
		}
	}
	if _, ok := Verify(secret, Code(secret, Step(now.Add(-90*time.Second))), now); ok {
		t.Error("code from 3 steps ago accepted")
	}
	if _, ok := Verify(secret, "12345", now); ok {
		t.Error("short code accepted")
	}
	c := Code(secret, Step(now))
	if _, ok := Verify(secret, c[:3]+" "+c[3:], now); !ok {
		t.Error("code with a space rejected")
	}
}

func TestURIAndRecovery(t *testing.T) {
	u := URI("Samba Conductor", "lab.admin@LAB.CONDUCTOR.TEST", []byte("12345678901234567890"))
	if !strings.HasPrefix(u, "otpauth://totp/Samba%20Conductor:lab.admin@LAB.CONDUCTOR.TEST?") || !strings.Contains(u, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
		t.Fatalf("uri %s", u)
	}
	codes, err := NewRecoveryCodes()
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] || !LooksLikeRecoveryCode(c) {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	h := HashRecoveryCode("S-1-5-21-1", codes[0])
	if HashRecoveryCode("S-1-5-21-1", strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))) != h {
		t.Error("normalization")
	}
	if HashRecoveryCode("S-1-5-21-2", codes[0]) == h {
		t.Error("hash not bound to the user")
	}
	if LooksLikeRecoveryCode("123456") {
		t.Error("TOTP code taken for a recovery code")
	}
}
