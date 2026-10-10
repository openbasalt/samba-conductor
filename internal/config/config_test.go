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
		"proxy w/o trusted":       proxyBody(""),
		"http public url":         withServer(`public_url = "http://dc1.example.com"`),
		"public url with path":    withServer(`public_url = "https://dc1.example.com/conductor"`),
	}
	for name, body := range cases {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := load(t, proxyBody(`trusted_proxies = ["127.0.0.1/32"]`)); err != nil {
		t.Errorf("loopback behind a proxy refused: %v", err)
	}
	if _, err := load(t, proxyBody("")); err == nil || !strings.Contains(err.Error(), "trusted_proxies is required") {
		t.Errorf("behind_proxy without trusted_proxies: %v", err)
	}
}

// withServer is base with a line added to [server].
func withServer(line string) string {
	return strings.Replace(base, `listen = ":8443"`, "listen = \":8443\"\n"+line, 1)
}

// proxyBody is base turned into a loopback listener behind a reverse proxy,
// with extra lines added to [server].
func proxyBody(extra string) string {
	return strings.Replace(strings.Replace(strings.Replace(base, `tls_cert = "/etc/conductor/tls/cert.pem"`, "behind_proxy = true\n"+extra, 1),
		`tls_key = "/etc/conductor/tls/key.pem"`, "", 1), `":8443"`, `"127.0.0.1:8080"`, 1)
}

func TestPublicBaseURL(t *testing.T) {
	c, err := load(t, base)
	if err != nil || c.PublicBaseURL() != "" {
		t.Fatalf("no public URL: %q %v", c.PublicBaseURL(), err)
	}
	// The WebAuthn origin is the fallback.
	c, err = load(t, base+"[webauthn]\nrp_id = \"dc1.lab.conductor.test\"\n")
	if err != nil || c.PublicBaseURL() != "https://dc1.lab.conductor.test:8443" {
		t.Fatalf("from rp_id: %q %v", c.PublicBaseURL(), err)
	}
	// server.public_url wins, without a trailing slash.
	c, err = load(t, withServer(`public_url = "https://conductor.example.com/"`)+"[webauthn]\nrp_id = \"dc1.lab.conductor.test\"\n")
	if err != nil || c.PublicBaseURL() != "https://conductor.example.com" {
		t.Fatalf("public_url: %q %v", c.PublicBaseURL(), err)
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

func TestBrandingKeys(t *testing.T) {
	c, err := load(t, base+`
[branding]
templates_dir = "/etc/conductor/templates"
allowed_origins = ["https://cdn.example.com"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Branding.TemplatesDir != "/etc/conductor/templates" || c.AllowedOrigins()[0] != "https://cdn.example.com" {
		t.Fatalf("%+v", c.Branding)
	}
	for _, bad := range []string{`templates_dir = "rel"`, `allowed_origins = ["http://cdn.example.com"]`} {
		if _, err := load(t, base+"\n[branding]\n"+bad+"\n"); err == nil || !strings.Contains(err.Error(), "branding") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestMailKeys(t *testing.T) {
	c, err := load(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mail.Enabled() || c.Mail.Port != 587 || c.Mail.Security != MailSTARTTLS || c.Mail.MaxPerHour != 200 {
		t.Fatalf("mail defaults %+v", c.Mail)
	}
	good := base + `
[mail]
host = "smtp.example.com"
port = 465
security = "tls"
username = "relay-user"
password_file = "/etc/conductor/smtp-password"
from = "Samba Conductor <no-reply@example.com>"
reply_to = "help@example.com"
hello_name = "dc1.example.com"
ca_file = "/etc/conductor/relay-ca.pem"
max_per_hour = 50
`
	c, err = load(t, good)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Mail.Enabled() || c.Mail.Port != 465 || c.Mail.MaxPerHour != 50 {
		t.Fatalf("%+v", c.Mail)
	}
	if p, err := c.MailPasswordPath(); err != nil || p != "/etc/conductor/smtp-password" {
		t.Fatalf("password path %q %v", p, err)
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		loopback := base + "[mail]\nhost = \"" + host + "\"\nport = 25\nsecurity = \"none\"\nfrom = \"no-reply@example.com\"\n"
		if _, err := load(t, loopback); err != nil {
			t.Errorf("plain SMTP to %s refused: %v", host, err)
		}
	}
	cases := map[string]string{
		"none to a remote host": "host = \"smtp.example.com\"\nsecurity = \"none\"\nfrom = \"a@example.com\"",
		"unknown security":      "host = \"smtp.example.com\"\nsecurity = \"ssl\"\nfrom = \"a@example.com\"",
		"port out of range":     "host = \"smtp.example.com\"\nport = 70000\nfrom = \"a@example.com\"",
		"no from":               "host = \"smtp.example.com\"",
		"from not an address":   "host = \"smtp.example.com\"\nfrom = \"nobody\"",
		"from with a newline":   "host = \"smtp.example.com\"\nfrom = \"a@example.com\\r\\nBcc: x@example.com\"",
		"bad reply_to":          "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nreply_to = \"x\"",
		"relative ca_file":      "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nca_file = \"ca.pem\"",
		"relative password":     "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nusername = \"u\"\npassword_file = \"pw\"",
		"password w/o username": "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\npassword_file = \"/etc/pw\"",
		"ceiling zero":          "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nmax_per_hour = 0",
		"host with a port":      "host = \"smtp.example.com:25\"\nfrom = \"a@example.com\"",
		"hello with a space":    "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nhello_name = \"a b\"",
		"unknown key":           "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\npassword = \"inline\"",
		"none to a LAN address": "host = \"192.168.1.10\"\nsecurity = \"none\"\nfrom = \"a@example.com\"",
		"reply_to injection":    "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nreply_to = \"b@example.com\\nBcc: c@example.com\"",
		"username control":      "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nusername = \"u\\r\\nx\"",
		"ceiling too high":      "host = \"smtp.example.com\"\nfrom = \"a@example.com\"\nmax_per_hour = 100001",
	}
	for name, body := range cases {
		if _, err := load(t, base+"[mail]\n"+body+"\n"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMailPasswordPath(t *testing.T) {
	c := Default()
	if p, err := c.MailPasswordPath(); err != nil || p != "" {
		t.Fatalf("no username: %q %v", p, err)
	}
	c.Mail.Username = "relay"
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, err := c.MailPasswordPath(); err == nil {
		t.Fatal("missing credential accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "smtp-password"), []byte("pw\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if p, err := c.MailPasswordPath(); err != nil || p != filepath.Join(dir, "smtp-password") {
		t.Fatalf("%q %v", p, err)
	}
}

func TestProvisionerKeys(t *testing.T) {
	c, err := load(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Provisioner.Enabled || c.Provisioner.Socket != "/run/conductor-provisioner/api.sock" {
		t.Fatalf("provisioner defaults %+v", c.Provisioner)
	}
	c, err = load(t, base+"[provisioner]\nenabled = true\nsocket = \"/run/p/api.sock\"\n")
	if err != nil || !c.Provisioner.Enabled || c.Provisioner.Socket != "/run/p/api.sock" {
		t.Fatalf("%+v %v", c.Provisioner, err)
	}
	for _, bad := range []string{"enabled = true\nsocket = \"rel.sock\"", "token = \"x\""} {
		if _, err := load(t, base+"[provisioner]\n"+bad+"\n"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
