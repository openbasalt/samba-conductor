// Package secret seals small secrets (TOTP keys) with AES-256-GCM under a
// key that comes from systemd credentials or a 0600 key file.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeySize is the AES-256 key length.
const KeySize = 32

// Box seals and opens values. Safe for concurrent use.
type Box struct{ aead cipher.AEAD }

// New builds a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret: key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// NewRandom builds a Box with a fresh random key that lives only in memory
// (used for per-process secrets such as a simple-bind password).
func NewRandom() (*Box, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return New(key)
}

// LoadKeyFile reads a key file holding 32 raw bytes or 64 hex digits. The
// file must not be readable by group or others, except a systemd
// credential: those are 0440 inside $CREDENTIALS_DIRECTORY, a directory
// only the service can open, so group read is accepted there.
func LoadKeyFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	forbidden := os.FileMode(0o077)
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && filepath.Dir(filepath.Clean(path)) == filepath.Clean(dir) {
		forbidden = 0o037
	}
	if st.Mode().Perm()&forbidden != 0 {
		return nil, fmt.Errorf("secret: %s is accessible by group or others (mode %v); use 0600", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return parseKey(b)
}

func parseKey(b []byte) ([]byte, error) {
	if len(b) == KeySize {
		return b, nil
	}
	s := strings.TrimSpace(string(b))
	if len(s) == 2*KeySize {
		k, err := hex.DecodeString(s)
		if err == nil {
			return k, nil
		}
	}
	return nil, errors.New("secret: key file must hold 32 raw bytes or 64 hex digits")
}

// GenerateKeyHex returns a new random key as 64 hex digits (for key files).
func GenerateKeyHex() (string, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// Seal encrypts plaintext; aad binds the ciphertext to its owner (e.g. the
// user SID) so a row copied to another user does not decrypt.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts a value produced by Seal with the same aad.
func (b *Box) Open(sealed, aad []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n+b.aead.Overhead() {
		return nil, errors.New("secret: sealed value too short")
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, errors.New("secret: cannot decrypt (wrong key or owner)")
	}
	return out, nil
}
