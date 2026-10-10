package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- settings ----

// Settings returns every stored setting (key to JSON value).
func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// PutSettings stores several settings in one transaction.
func (s *Store) PutSettings(ctx context.Context, values map[string]string, by string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := ts(s.now())
	for k, v := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			clip(k, 128), clip(v, 4096), now, clip(by, 256)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- recovery addresses ----

// RecoveryEmail is a user's verified recovery address.
type RecoveryEmail struct {
	UserSID          string
	Address          string
	VerifiedAt       time.Time
	ChangedAt        time.Time
	PreviousNotified bool
}

// GetRecoveryEmail returns a user's recovery address or ErrNotFound.
func (s *Store) GetRecoveryEmail(ctx context.Context, userSID string) (RecoveryEmail, error) {
	var r RecoveryEmail
	var verified, changed string
	var notified int
	err := s.db.QueryRowContext(ctx, `SELECT user_sid, address, verified_at, changed_at, previous_notified FROM recovery_emails WHERE user_sid = ?`,
		userSID).Scan(&r.UserSID, &r.Address, &verified, &changed, &notified)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.VerifiedAt, r.ChangedAt, r.PreviousNotified = parseTS(verified), parseTS(changed), notified != 0
	return r, nil
}

// SetRecoveryEmail stores a verified recovery address (replacing any).
func (s *Store) SetRecoveryEmail(ctx context.Context, r RecoveryEmail) error {
	notified := 0
	if r.PreviousNotified {
		notified = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO recovery_emails(user_sid, address, verified_at, changed_at, previous_notified) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_sid) DO UPDATE SET address = excluded.address, verified_at = excluded.verified_at, changed_at = excluded.changed_at,
		previous_notified = excluded.previous_notified`, r.UserSID, clip(r.Address, 254), ts(r.VerifiedAt), ts(r.ChangedAt), notified)
	return err
}

// DeleteRecoveryEmail removes a user's recovery address.
func (s *Store) DeleteRecoveryEmail(ctx context.Context, userSID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM recovery_emails WHERE user_sid = ?`, userSID)
	return err
}

// ---- tokens conductor asked conductor-provisioner for ----

// LinkToken is conductor's record of an issued one-time token.
type LinkToken struct {
	TokenID    string
	Purpose    string
	UserSID    string
	Username   string
	Lang       string
	IssuerSID  string
	IssuerName string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	ReissueOf  string
	Handled    bool
}

// PutLinkToken records an issued token.
func (s *Store) PutLinkToken(ctx context.Context, t LinkToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO link_tokens(token_id, purpose, user_sid, username, lang, issuer_sid, issuer_name, issued_at,
		expires_at, reissue_of, handled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, t.TokenID, t.Purpose, t.UserSID, clip(t.Username, 256),
		t.Lang, t.IssuerSID, clip(t.IssuerName, 256), ts(t.IssuedAt), ts(t.ExpiresAt), t.ReissueOf, boolInt(t.Handled))
	return err
}

// GetLinkToken returns a token record or ErrNotFound.
func (s *Store) GetLinkToken(ctx context.Context, tokenID string) (LinkToken, error) {
	rows, err := s.linkTokens(ctx, `WHERE token_id = ?`, tokenID)
	if err != nil {
		return LinkToken{}, err
	}
	if len(rows) == 0 {
		return LinkToken{}, ErrNotFound
	}
	return rows[0], nil
}

// ExpiredInvites returns the invitations that expired before now and the
// re-issue sweep has not looked at yet.
func (s *Store) ExpiredInvites(ctx context.Context, now time.Time, limit int) ([]LinkToken, error) {
	return s.linkTokens(ctx, `WHERE purpose = 'invite' AND handled = 0 AND expires_at < ? ORDER BY expires_at LIMIT ?`, ts(now), limit)
}

// MarkLinkTokenHandled records that the re-issue sweep looked at a token.
func (s *Store) MarkLinkTokenHandled(ctx context.Context, tokenID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE link_tokens SET handled = 1 WHERE token_id = ?`, tokenID)
	return err
}

// PruneLinkTokens drops records that expired before the given time.
func (s *Store) PruneLinkTokens(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM link_tokens WHERE expires_at < ? AND (handled = 1 OR purpose <> 'invite')`, ts(before))
	return err
}

func (s *Store) linkTokens(ctx context.Context, where string, args ...any) ([]LinkToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token_id, purpose, user_sid, username, lang, issuer_sid, issuer_name, issued_at, expires_at,
		reissue_of, handled FROM link_tokens `+where, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []LinkToken
	for rows.Next() {
		var t LinkToken
		var issued, expires string
		var handled int
		if err := rows.Scan(&t.TokenID, &t.Purpose, &t.UserSID, &t.Username, &t.Lang, &t.IssuerSID, &t.IssuerName, &issued, &expires,
			&t.ReissueOf, &handled); err != nil {
			return nil, err
		}
		t.IssuedAt, t.ExpiresAt, t.Handled = parseTS(issued), parseTS(expires), handled != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
