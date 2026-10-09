// Package totp implements RFC 6238 time-based one-time passwords (SHA-1,
// 6 digits, 30-second steps: what every authenticator app supports) and
// the recovery codes that back them up.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // HMAC-SHA-1 is what RFC 6238 authenticator apps implement
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	// Period is the time step.
	Period = 30 * time.Second
	// Digits of a code.
	Digits = 6
	// SecretSize is the secret length in bytes (160 bits, RFC 4226).
	SecretSize = 20
	// Skew is how many steps before/after now are accepted.
	Skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretSize)
	_, err := rand.Read(s)
	return s, err
}

// EncodeSecret renders a secret in base32 for manual entry.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// Step returns the time step of t.
func Step(t time.Time) int64 { return t.Unix() / int64(Period/time.Second) }

// Code computes the code for a step (RFC 4226 HOTP with the step as counter).
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// Verify checks code against the steps around now and returns the matching
// step. Callers must reject a step that is not newer than the last one
// accepted for the same user (replay protection).
func Verify(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	var found int64
	ok := 0
	for d := int64(-Skew); d <= Skew; d++ {
		// Constant-time comparison over every candidate step.
		if subtle.ConstantTimeCompare([]byte(Code(secret, cur+d)), []byte(code)) == 1 {
			found = cur + d
			ok = 1
		}
	}
	return found, ok == 1
}

// URI is the otpauth:// URI that authenticator apps scan.
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// RecoveryCodeCount codes are issued at a time.
const RecoveryCodeCount = 10

var recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes returns fresh single-use codes ("xxxxx-xxxxx", about 49
// bits each) to show once to the user.
func NewRecoveryCodes() ([]string, error) {
	out := make([]string, RecoveryCodeCount)
	for i := range out {
		c, err := recoveryCode(rand.Reader)
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

// recoveryCode draws one code from r. Each symbol is uniform over the
// alphabet: bytes at or above the largest multiple of its size are
// rejected and drawn again, so the modulo does not favour any symbol.
func recoveryCode(r io.Reader) (string, error) {
	sym, err := uniformSymbols(r, recoveryAlphabet, 10)
	if err != nil {
		return "", err
	}
	return string(sym[:5]) + "-" + string(sym[5:]), nil
}

// uniformSymbols returns n symbols of alphabet (at most 256 of them) drawn
// uniformly from the bytes of r by rejection sampling.
func uniformSymbols(r io.Reader, alphabet string, n int) ([]byte, error) {
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		chunk := buf[:n-len(out)]
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		for _, c := range chunk {
			if int(c) < limit {
				out = append(out, alphabet[int(c)%len(alphabet)])
			}
		}
	}
	return out, nil
}

// HashRecoveryCode normalizes and hashes a code for storage. The codes are
// random (50 bits), so a plain SHA-256 is enough; the user SID is mixed in
// so equal codes of two users do not share a hash.
func HashRecoveryCode(userSID, code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	if len(code) == 10 {
		code = code[:5] + "-" + code[5:]
	}
	h := sha256.Sum256([]byte("conductor-recovery\x00" + userSID + "\x00" + code))
	return hex.EncodeToString(h[:])
}

// LooksLikeRecoveryCode distinguishes a recovery code from a TOTP code.
func LooksLikeRecoveryCode(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) == 11 && s[5] == '-' || len(s) == 10 && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0
}
