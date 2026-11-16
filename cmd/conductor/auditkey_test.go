package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
)

func TestCLIAuditKeyPath(t *testing.T) {
	c := config.Default()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if p := cliAuditKeyPath(c); p != config.DefaultAuditKeyFile {
		t.Fatalf("default %q", p)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/x")
	if p := cliAuditKeyPath(c); p != "/run/credentials/x/audit-key" {
		t.Fatalf("credential %q", p)
	}
	c.Audit.KeyFile = "/k"
	if p := cliAuditKeyPath(c); p != "/k" {
		t.Fatalf("key_file %q", p)
	}
}

func TestOpenStoreCLI(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as an unprivileged owner")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	dir := t.TempDir()
	c := config.Default()
	c.State.Database = filepath.Join(dir, "c.db")
	c.Audit.KeyFile = filepath.Join(dir, "audit-key")
	ctx := context.Background()
	// No key file: verify-type commands fail and say why.
	if _, err := openStoreCLI(ctx, c, dir, true); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("missing key: %v", err)
	}
	if err := os.WriteFile(c.Audit.KeyFile, []byte(strings.Repeat("ab", 32)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openStoreCLI(ctx, c, dir, true); err == nil {
		t.Fatal("a key readable by others was accepted")
	}
	if err := os.Chmod(c.Audit.KeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := openStoreCLI(ctx, c, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var logged []store.AuditEvent
	st.SetAuditSink(func(e store.AuditEvent) { logged = append(logged, e) })
	if _, err := st.AppendAudit(ctx, store.AuditEvent{Action: "mfa.enroll_link"}); err != nil {
		t.Fatal(err)
	}
	if res, err := st.VerifyAudit(ctx); err != nil || res.BrokenAt != 0 || res.KeyedFrom != 1 || len(logged) != 1 {
		t.Fatalf("verify %+v %v %d", res, err, len(logged))
	}
}
