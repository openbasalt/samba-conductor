package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	b, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := b.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("S-1-5-21-1-2-3-1105"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open(sealed, []byte("S-1-5-21-1-2-3-1105"))
	if err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := b.Open(sealed, []byte("S-1-5-21-1-2-3-1106")); err == nil {
		t.Error("opened with another owner")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := b.Open(sealed, []byte("S-1-5-21-1-2-3-1105")); err == nil {
		t.Error("opened a tampered value")
	}
	other, _ := NewRandom()
	s2, _ := b.Seal([]byte("x"), nil)
	if _, err := other.Open(s2, nil); err == nil {
		t.Error("opened with another key")
	}
}

func TestLoadKeyFile(t *testing.T) {
	dir := t.TempDir()
	hexKey, _ := GenerateKeyHex()
	p := filepath.Join(dir, "k")
	if err := os.WriteFile(p, []byte(hexKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadKeyFile(p)
	if err != nil || len(k) != KeySize {
		t.Fatalf("hex key: %v", err)
	}
	raw := filepath.Join(dir, "raw")
	_ = os.WriteFile(raw, bytes.Repeat([]byte{7}, KeySize), 0o400)
	if _, err := LoadKeyFile(raw); err != nil {
		t.Fatalf("raw key: %v", err)
	}
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte(hexKey), 0o644)
	if _, err := LoadKeyFile(loose); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	// A systemd credential (0440 in the private credentials directory).
	credDir := t.TempDir()
	cred := filepath.Join(credDir, "totp-key")
	_ = os.WriteFile(cred, []byte(hexKey), 0o440)
	if _, err := LoadKeyFile(cred); err == nil {
		t.Error("group-readable key accepted outside the credentials directory")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	if _, err := LoadKeyFile(cred); err != nil {
		t.Errorf("systemd credential refused: %v", err)
	}
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("abcd"), 0o600)
	if _, err := LoadKeyFile(short); err == nil {
		t.Error("short key accepted")
	}
}
