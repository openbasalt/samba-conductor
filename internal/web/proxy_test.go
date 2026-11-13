package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
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

// A proxy that adds its own X-Forwarded-For line (instead of extending the
// client's) must not let the client's line decide the address.
func TestClientIPMultipleForwardedLines(t *testing.T) {
	h := newHarness(t, behindProxy("127.0.0.1/32"))
	r := httptest.NewRequest("GET", "https://"+testHost+"/signin", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	r.Header.Add("X-Forwarded-For", "203.0.113.5")
	if got := h.s.clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want the proxy's entry", got)
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Add("X-Forwarded-For", "198.51.100.7, 192.0.2.1")
	r.Header.Add("X-Forwarded-For", "203.0.113.5, 127.0.0.1")
	if got := h.s.clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP over a proxy chain = %q", got)
	}
}

// The sign-in limit per address groups an IPv6 client by its /64 (a new
// address of the same /64 gets no new budget) and keeps IPv4 per address;
// the audit log records the full address.
func TestSigninRateLimitIPv6Prefix(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.RateLimit.PerIPPerMinute = 2 })
	signinFrom := func(remote string) int {
		from := func(r *http.Request) { r.RemoteAddr = remote }
		w := h.do("GET", "/signin", "", nil, from)
		var pre string
		for _, c := range w.Result().Cookies() {
			if c.Name == preCookie {
				pre = c.Value
			}
		}
		form := url.Values{"csrf": {pre}, "username": {"nobody"}, "password": {"wrong"}}
		return h.do("POST", "/signin", "", form, from, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: preCookie, Value: pre})
		}).Code
	}
	for i := range 2 {
		if c := signinFrom(fmt.Sprintf("[2001:db8:1:2::%x]:40000", i+1)); c == http.StatusTooManyRequests {
			t.Fatalf("attempt %d limited too early", i)
		}
	}
	if c := signinFrom("[2001:db8:1:2:ffff::9]:40000"); c != http.StatusTooManyRequests {
		t.Fatalf("another address of the same /64 got a new budget: %d", c)
	}
	if c := signinFrom("[2001:db8:1:3::1]:40000"); c == http.StatusTooManyRequests {
		t.Fatal("another /64 shares the bucket")
	}
	for _, ip := range []string{"192.0.2.21", "192.0.2.22"} {
		if c := signinFrom(ip + ":40000"); c == http.StatusTooManyRequests {
			t.Fatalf("IPv4 %s limited by another address", ip)
		}
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "signin.rate_limited"}, 0, 10)
	if len(evs) == 0 || evs[0].IP != "2001:db8:1:2:ffff::9" {
		t.Fatalf("rate limit audit does not keep the full address: %+v", evs)
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
