// Package store is conductor's local state in SQLite (pure Go driver, CGO
// off): session metadata, second-factor enrollments, enrollment links and
// the hash-chained audit log. The directory itself is never copied here:
// AD stays the source of truth.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store wraps the database.
type Store struct {
	db *sql.DB
	// auditMu serializes appends so the chain has no forks.
	auditMu sync.Mutex
	now     func() time.Time
}

// Open opens (creating if needed) the database at path and applies the
// embedded migrations. The file is made private to the process user.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty path")
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	if path == ":memory:" {
		dsn = "file::memory:?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; one connection also keeps :memory: shared.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" {
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			if _, err := os.Stat(p); err == nil {
				_ = os.Chmod(p, 0o600)
			}
		}
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		v, err := strconv.Atoi(strings.SplitN(path.Base(name), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: migration %s: bad name", name)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, v).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, v, ts(s.now())); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// ---- sessions (metadata) ----

// SessionRow is the stored part of a session.
type SessionRow struct {
	IDHash     string
	UserSID    string
	Username   string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
}

// PutSession inserts or replaces a session row.
func (s *Store) PutSession(ctx context.Context, r SessionRow) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO sessions(id_hash, user_sid, username, created_at, last_seen_at, expires_at, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, r.IDHash, r.UserSID, r.Username, ts(r.CreatedAt), ts(r.LastSeenAt), ts(r.ExpiresAt), r.IP, clip(r.UserAgent, 256))
	return err
}

// TouchSession records activity.
func (s *Store) TouchSession(ctx context.Context, idHash string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, ts(at), idHash)
	return err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions removes every session of a user and returns their hashes.
func (s *Store) DeleteUserSessions(ctx context.Context, userSID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `DELETE FROM sessions WHERE user_sid = ? RETURNING id_hash`, userSID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DeleteAllSessions clears the table (at startup).
func (s *Store) DeleteAllSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

// UserSessions lists a user's sessions, newest first.
func (s *Store) UserSessions(ctx context.Context, userSID string) ([]SessionRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id_hash, user_sid, username, created_at, last_seen_at, expires_at, ip, user_agent
		FROM sessions WHERE user_sid = ? ORDER BY created_at DESC`, userSID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		var c, l, e string
		if err := rows.Scan(&r.IDHash, &r.UserSID, &r.Username, &c, &l, &e, &r.IP, &r.UserAgent); err != nil {
			return nil, err
		}
		r.CreatedAt, r.LastSeenAt, r.ExpiresAt = parseTS(c), parseTS(l), parseTS(e)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- TOTP ----

// TOTPRecord is a user's enrollment.
type TOTPRecord struct {
	UserSID   string
	Username  string
	Secret    []byte // sealed
	CreatedAt time.Time
	LastStep  int64
}

// ErrNotFound is returned for a missing row.
var ErrNotFound = errors.New("store: not found")

// GetTOTP returns the enrollment of a user or ErrNotFound.
func (s *Store) GetTOTP(ctx context.Context, userSID string) (TOTPRecord, error) {
	var r TOTPRecord
	var c string
	err := s.db.QueryRowContext(ctx, `SELECT user_sid, username, secret, created_at, last_step FROM mfa_totp WHERE user_sid = ?`, userSID).
		Scan(&r.UserSID, &r.Username, &r.Secret, &c, &r.LastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	r.CreatedAt = parseTS(c)
	return r, err
}

// EnrollTOTP stores a verified enrollment (replacing an old one) together
// with fresh recovery code hashes, and marks the step used for the
// verification so it cannot be replayed.
func (s *Store) EnrollTOTP(ctx context.Context, r TOTPRecord, recoveryHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO mfa_totp(user_sid, username, secret, created_at, last_step) VALUES (?, ?, ?, ?, ?)`,
		r.UserSID, r.Username, r.Secret, ts(s.now()), r.LastStep); err != nil {
		return err
	}
	if err := replaceCodes(ctx, tx, r.UserSID, recoveryHashes); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceCodes(ctx context.Context, tx *sql.Tx, userSID string, hashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_sid = ?`, userSID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO mfa_recovery_codes(user_sid, code_hash) VALUES (?, ?)`, userSID, h); err != nil {
			return err
		}
	}
	return nil
}

// UseTOTPStep records step as used if it is newer than the last accepted
// one. False means a replay (or an older code).
func (s *Store) UseTOTPStep(ctx context.Context, userSID string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mfa_totp SET last_step = ? WHERE user_sid = ? AND last_step < ?`, step, userSID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DeleteTOTP removes a user's second factor and recovery codes.
func (s *Store) DeleteTOTP(ctx context.Context, userSID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_totp WHERE user_sid = ?`, userSID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_sid = ?`, userSID); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceRecoveryCodes swaps a user's recovery codes.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userSID string, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceCodes(ctx, tx, userSID, hashes); err != nil {
		return err
	}
	return tx.Commit()
}

// UseRecoveryCode consumes an unused code; false if unknown or used.
func (s *Store) UseRecoveryCode(ctx context.Context, userSID, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mfa_recovery_codes SET used_at = ? WHERE user_sid = ? AND code_hash = ? AND used_at IS NULL`,
		ts(s.now()), userSID, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecoveryCodesLeft counts unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userSID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_sid = ? AND used_at IS NULL`, userSID).Scan(&n)
	return n, err
}

// ---- enrollment links ----

// CreateEnrollLink stores a link token hash for username (lower-cased).
func (s *Store) CreateEnrollLink(ctx context.Context, tokenHash, username, createdBy string, ttl time.Duration) error {
	now := s.now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO enroll_links(token_hash, username, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		tokenHash, strings.ToLower(username), createdBy, ts(now), ts(now.Add(ttl)))
	return err
}

// ValidEnrollLink reports whether an unused, unexpired link for username exists.
func (s *Store) ValidEnrollLink(ctx context.Context, tokenHash, username string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enroll_links WHERE token_hash = ? AND username = ? AND used_at IS NULL AND expires_at > ?`,
		tokenHash, strings.ToLower(username), ts(s.now())).Scan(&n)
	return n == 1, err
}

// ConsumeEnrollLink marks the link used; false if it was not valid.
func (s *Store) ConsumeEnrollLink(ctx context.Context, tokenHash, username string) (bool, error) {
	now := s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE enroll_links SET used_at = ? WHERE token_hash = ? AND username = ? AND used_at IS NULL AND expires_at > ?`,
		ts(now), tokenHash, strings.ToLower(username), ts(now))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
