package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openbasalt/samba-conductor/internal/config"
)

// TestRenderedConfigLoads: what setup writes is a valid configuration,
// with WebAuthn on (rp_id from --public-url) and off.
func TestRenderedConfigLoads(t *testing.T) {
	for _, o := range []setupOpts{
		{listen: ":8443", tlsCert: "/etc/conductor/tls/cert.pem", tlsKey: "/etc/conductor/tls/key.pem", realm: "LAB.EXAMPLE.TEST",
			dc: "dc1.lab.example.test", mfaPolicy: config.MFAOptional, publicURL: "https://dc1.lab.example.test:8443"},
		{listen: ":8443", behindProxy: true, realm: "LAB.EXAMPLE.TEST", dc: "dc1.lab.example.test", mfaPolicy: config.MFARequired},
	} {
		b, err := renderConfig(o, "/etc/conductor/domain-ca.pem", config.Roles{HelpdeskGroups: []string{"S-1-5-21-1-2-3-1105"}})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "conductor.toml")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(p)
		if err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
		if (o.publicURL != "") != c.WebAuthn.Enabled() {
			t.Fatalf("webauthn enabled=%v for %+v", c.WebAuthn.Enabled(), o)
		}
		if o.publicURL != "" && c.WebAuthnOrigins()[0] != "https://dc1.lab.example.test:8443" {
			t.Fatalf("origins %v", c.WebAuthnOrigins())
		}
	}
}
