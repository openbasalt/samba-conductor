package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor/internal/config"
)

// behindProxy configures the harness like a loopback listener behind a
// reverse proxy on the same host.
func behindProxy(trusted ...string) func(*config.Config) {
	return func(c *config.Config) {
		c.Server.TLSCert, c.Server.TLSKey = "", ""
		c.Server.Listen = "127.0.0.1:8080"
		c.Server.BehindProxy = true
		c.Server.TrustedProxies = trusted
	}
}

func TestClientIPBehindProxy(t *testing.T) {
	h := newHarness(t, behindProxy("127.0.0.1/32", "::1/128"))
	for name, tc := range map[string]struct {
		peer, xff, want string
	}{
		// A client that reaches the listener directly cannot choose its
		// address through X-Forwarded-For.
		"untrusted peer, spoofed loopback":  {"192.0.2.10:40000", "127.0.0.1", "192.0.2.10"},
		"untrusted peer, spoofed client":    {"192.0.2.10:40000", "203.0.113.5", "192.0.2.10"},
		"untrusted peer, no header":         {"192.0.2.10:40000", "", "192.0.2.10"},
		"trusted proxy":                     {"127.0.0.1:50000", "203.0.113.5", "203.0.113.5"},
		"trusted proxy over IPv6":           {"[::1]:50000", "203.0.113.5", "203.0.113.5"},
		"client-supplied entry is ignored":  {"127.0.0.1:50000", "198.51.100.7, 203.0.113.5", "203.0.113.5"},
		"chain of trusted proxies":          {"127.0.0.1:50000", "203.0.113.5, 127.0.0.1", "203.0.113.5"},
		"trusted proxy, no header":          {"127.0.0.1:50000", "", "127.0.0.1"},
		"trusted proxy, malformed entry":    {"127.0.0.1:50000", "not-an-ip", "127.0.0.1"},
		"mapped IPv4 peer is still trusted": {"[::ffff:127.0.0.1]:50000", "203.0.113.5", "203.0.113.5"},
	} {
		r := httptest.NewRequest("GET", "https://"+testHost+"/signin", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := h.s.clientIP(r); got != tc.want {
			t.Errorf("%s: clientIP = %q, want %q", name, got, tc.want)
		}
	}
}

// Without trusted proxies the header is never believed (config.Validate
// refuses that combination; this keeps the code safe on its own).
func TestClientIPNoTrustedProxies(t *testing.T) {
	h := newHarness(t, behindProxy())
	r := httptest.NewRequest("GET", "https://"+testHost+"/signin", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	if got := h.s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("clientIP = %q", got)
	}
}

// Two clients behind the proxy get separate sign-in rate limit buckets.
func TestRateLimitPerClientBehindProxy(t *testing.T) {
	h := newHarness(t, behindProxy("127.0.0.1/32"), func(c *config.Config) { c.RateLimit.PerIPPerMinute = 2 })
	from := func(client string) int {
		r := httptest.NewRequest("GET", "https://"+testHost+"/signin", nil)
		r.RemoteAddr = "127.0.0.1:50000"
		r.Header.Set("X-Forwarded-For", client)
		if h.s.ipLimit.Allow("signin:" + h.s.clientIP(r)) {
			return http.StatusOK
		}
		return http.StatusTooManyRequests
	}
	for range 2 {
		if from("203.0.113.5") != http.StatusOK {
			t.Fatal("first client limited too early")
		}
	}
	if from("203.0.113.5") != http.StatusTooManyRequests {
		t.Fatal("first client not limited")
	}
	if from("203.0.113.6") != http.StatusOK {
		t.Fatal("second client shares the first client's bucket")
	}
}

func TestEnrollLinkNeedsPublicURL(t *testing.T) {
	const path = "/admin/users/00112233-4455-6677-8899-aabbccddeeff/mfa/link"
	h := newHarness(t)
	tok := h.session(t, "lab.admin", stageFull, true)
	// No public URL: refused before the directory is asked, whatever Host
	// the request carries.
	w := h.do("POST", path, tok, nil, withHeader("Sec-Fetch-Site", "same-origin"), withHeader("Origin", "https://"+testHost))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "server.public_url") {
		t.Fatalf("without public_url: %d", w.Code)
	}
	// With a public URL the request goes on to the directory (which the
	// fake backend does not have).
	h = newHarness(t, func(c *config.Config) { c.Server.PublicURL = "https://conductor.example.com" })
	tok = h.session(t, "lab.admin", stageFull, true)
	w = h.do("POST", path, tok, nil, withHeader("Sec-Fetch-Site", "same-origin"), withHeader("Origin", "https://"+testHost))
	if w.Code == http.StatusConflict || strings.Contains(w.Body.String(), "server.public_url") {
		t.Fatalf("with public_url: %d", w.Code)
	}
}
