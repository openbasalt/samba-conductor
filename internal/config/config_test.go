package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const base = `
[server]
listen = ":8443"
tls_cert = "/etc/conductor/tls/cert.pem"
tls_key = "/etc/conductor/tls/key.pem"
[domain]
realm = "LAB.CONDUCTOR.TEST"
ca_file = "/etc/conductor/domain-ca.pem"
[roles]
helpdesk_groups = ["S-1-5-21-1-2-3-1105"]
`

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadDefaults(t *testing.T) {
	c, err := load(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.IdleMinutes != 15 || c.Session.AbsoluteHours != 8 || c.MFA.Policy != MFAOptional ||
		!c.DelegatedMFARequired() || !c.AdminEnrollmentLinkRequired() || c.RoleCacheTTL().Seconds() != 60 || !c.TLS() {
		t.Fatalf("defaults %+v", c)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"unknown key":             base + "\n[server2]\nx = 1\n",
		"typo in a section":       strings.Replace(base, "listen", "lisen", 1),
		"plain http public":       strings.Replace(strings.Replace(base, `tls_cert = "/etc/conductor/tls/cert.pem"`, "behind_proxy = true", 1), `tls_key = "/etc/conductor/tls/key.pem"`, "", 1),
		"no tls at all":           strings.Replace(strings.Replace(base, `tls_cert = "/etc/conductor/tls/cert.pem"`, "", 1), `tls_key = "/etc/conductor/tls/key.pem"`, "", 1),
		"group name not SID":      strings.Replace(base, `"S-1-5-21-1-2-3-1105"`, `"Helpdesk"`, 1),
		"relative CA":             strings.Replace(base, "/etc/conductor/domain-ca.pem", "ca.pem", 1),
		"role cache over 60s":     base + "cache_seconds = 300\n",
		"bad mfa policy":          base + "[mfa]\npolicy = \"sometimes\"\n",
		"session too long":        base + "[session]\nabsolute_hours = 72\n",
		"trusted proxy w/o proxy": strings.Replace(base, `listen = ":8443"`, "listen = \":8443\"\ntrusted_proxies = [\"127.0.0.1/32\"]", 1),
	}
	for name, body := range cases {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	proxy := strings.Replace(strings.Replace(strings.Replace(base, `tls_cert = "/etc/conductor/tls/cert.pem"`, "behind_proxy = true\ntrusted_proxies = [\"127.0.0.1/32\"]", 1),
		`tls_key = "/etc/conductor/tls/key.pem"`, "", 1), `":8443"`, `"127.0.0.1:8080"`, 1)
	if _, err := load(t, proxy); err != nil {
		t.Errorf("loopback behind a proxy refused: %v", err)
	}
}

func TestMFAKeyPath(t *testing.T) {
	c := Default()
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/conductor.service")
	if p, err := c.MFAKeyPath(); err != nil || p != "/run/credentials/conductor.service/totp-key" {
		t.Fatalf("%q %v", p, err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := c.MFAKeyPath(); err == nil {
		t.Fatal("no key source accepted")
	}
}

func TestWebAuthnAndBulk(t *testing.T) {
	c, err := load(t, base)
	if err != nil || c.WebAuthn.Enabled() || c.Bulk.MaxRows != 1000 || c.Tools.SambaTool != "/usr/bin/samba-tool" {
		t.Fatalf("defaults %+v %v", c, err)
	}
	c, err = load(t, base+"[webauthn]\nrp_id = \"dc1.lab.conductor.test\"\nadmin_required = true\n")
	if err != nil || !c.WebAuthn.Enabled() {
		t.Fatal(err)
	}
	if o := c.WebAuthnOrigins(); len(o) != 1 || o[0] != "https://dc1.lab.conductor.test:8443" {
		t.Fatalf("default origins %v", o)
	}
	for name, body := range map[string]string{
		"rp id with scheme":       "[webauthn]\nrp_id = \"https://x.example\"\n",
		"http origin":             "[webauthn]\nrp_id = \"x.example\"\norigins = [\"http://x.example\"]\n",
		"origin of another site":  "[webauthn]\nrp_id = \"x.example\"\norigins = [\"https://evil.example\"]\n",
		"admin required, no rpid": "[webauthn]\nadmin_required = true\n",
		"bulk rows":               "[bulk]\nmax_rows = 0\n",
		"relative samba-tool":     "[tools]\nsamba_tool = \"samba-tool\"\n",
	} {
		if _, err := load(t, base+body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := load(t, base+"[webauthn]\nrp_id = \"lab.conductor.test\"\norigins = [\"https://dc1.lab.conductor.test:8443\"]\n"); err != nil {
		t.Errorf("subdomain origin refused: %v", err)
	}
}

// TestExampleLoads keeps conductor.toml.example valid.
func TestExampleLoads(t *testing.T) {
	if _, err := Load("../../conductor.toml.example"); err != nil {
		t.Fatal(err)
	}
}
