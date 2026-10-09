package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Mail log statuses.
const (
	MailQueued   = "queued"
	MailRetrying = "retrying"
	MailSent     = "sent"
	MailFailed   = "failed"
	MailExpired  = "expired"
)

// MailRow is a queued message; the Sealed fields are opaque here (the
// mail package seals and opens them).
type MailRow struct {
	ID              string
	Kind            string
	RecipientSealed []byte
	SubjectSealed   []byte
	TextSealed      []byte
	HTMLSealed      []byte
	Reference       string
	RecipientDomain string // for the log row only; not stored in the queue
	CreatedAt       time.Time
	NextAt          time.Time
	Attempts        int
	LastError       string
	ExpiresAt       time.Time
}

// MailLogRow is what the log keeps of a message: no content, no recipient
// beyond its domain.
type MailLogRow struct {
	ID              string
	Kind            string
	RecipientDomain string
	Reference       string
	Status          string
	Attempts        int
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SentAt          time.Time
	Error           string
}

// MailStats summarizes the queue and the log.
type MailStats struct {
	// Pending messages in the queue, of which Retrying failed at least once.
	Pending  int
	Retrying int
	// Sent and Failed (refused or expired) since the given time.
	Sent   int
	Failed int
}

// EnqueueMail inserts a queued message and its log row.
func (s *Store) EnqueueMail(ctx context.Context, r MailRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_queue(id, kind, recipient_sealed, subject_sealed, body_text_sealed, body_html_sealed,
		reference, created_at, next_at, attempts, last_error, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)`,
		r.ID, r.Kind, r.RecipientSealed, r.SubjectSealed, r.TextSealed, r.HTMLSealed, clip(r.Reference, 128),
		ts(r.CreatedAt), ts(r.NextAt), ts(r.ExpiresAt)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_log(id, kind, recipient_domain, reference, status, attempts, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?)`, r.ID, r.Kind, clip(r.RecipientDomain, 253), clip(r.Reference, 128), MailQueued,
		ts(r.CreatedAt), ts(r.CreatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

const mailCols = `id, kind, recipient_sealed, subject_sealed, body_text_sealed, body_html_sealed, reference, created_at, next_at,
	attempts, last_error, expires_at`

// DueMail returns up to limit queued messages whose next attempt is due,
// oldest first.
func (s *Store) DueMail(ctx context.Context, now time.Time, limit int) ([]MailRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+mailCols+` FROM mail_queue WHERE next_at <= ? ORDER BY next_at, created_at LIMIT ?`, ts(now), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MailRow
	for rows.Next() {
		var r MailRow
		var c, n, e string
		if err := rows.Scan(&r.ID, &r.Kind, &r.RecipientSealed, &r.SubjectSealed, &r.TextSealed, &r.HTMLSealed, &r.Reference,
			&c, &n, &r.Attempts, &r.LastError, &e); err != nil {
			return nil, err
		}
		r.CreatedAt, r.NextAt, r.ExpiresAt = parseTS(c), parseTS(n), parseTS(e)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RetryMail records a failed attempt (at) and when to try again (next).
func (s *Store) RetryMail(ctx context.Context, id string, attempts int, next, at time.Time, lastErr string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE mail_queue SET attempts = ?, next_at = ?, last_error = ? WHERE id = ?`,
		attempts, ts(next), clip(lastErr, 512), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mail_log SET status = ?, attempts = ?, error = ?, updated_at = ? WHERE id = ?`,
		MailRetrying, attempts, clip(lastErr, 512), ts(at), id); err != nil {
		return err
	}
	return tx.Commit()
}

// FinishMail deletes a message from the queue (with its sealed content)
// and records its final status: sent, failed or expired.
func (s *Store) FinishMail(ctx context.Context, id, status string, attempts int, at time.Time, lastErr string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_queue WHERE id = ?`, id); err != nil {
		return err
	}
	sent := ""
	if status == MailSent {
		sent = ts(at)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mail_log SET status = ?, attempts = ?, error = ?, updated_at = ?, sent_at = ? WHERE id = ?`,
		status, attempts, clip(lastErr, 512), ts(at), sent, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ExpiredMail returns the ids and attempts of queued messages past their
// expiry.
func (s *Store) ExpiredMail(ctx context.Context, now time.Time) ([]MailRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, attempts, last_error FROM mail_queue WHERE expires_at <= ?`, ts(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MailRow
	for rows.Next() {
		var r MailRow
		if err := rows.Scan(&r.ID, &r.Attempts, &r.LastError); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MailSentSince counts the messages the relay accepted since t (the
// hourly ceiling survives a restart this way).
func (s *Store) MailSentSince(ctx context.Context, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_log WHERE status = ? AND sent_at >= ?`, MailSent, ts(t)).Scan(&n)
	return n, err
}

// MailStats counts the queue, and the sent and failed messages since t.
func (s *Store) MailStats(ctx context.Context, since time.Time) (MailStats, error) {
	var st MailStats
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(attempts > 0), 0) FROM mail_queue`).Scan(&st.Pending, &st.Retrying); err != nil {
		return st, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(status = ?), 0), COALESCE(SUM(status IN (?, ?)), 0) FROM mail_log WHERE updated_at >= ?`,
		MailSent, MailFailed, MailExpired, ts(since)).Scan(&st.Sent, &st.Failed); err != nil {
		return st, err
	}
	return st, nil
}

// MailLog returns the newest log rows.
func (s *Store) MailLog(ctx context.Context, limit int) ([]MailLogRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, recipient_domain, reference, status, attempts, created_at, updated_at, sent_at, error
		FROM mail_log ORDER BY created_at DESC, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MailLogRow
	for rows.Next() {
		var r MailLogRow
		var c, u, sent string
		if err := rows.Scan(&r.ID, &r.Kind, &r.RecipientDomain, &r.Reference, &r.Status, &r.Attempts, &c, &u, &sent, &r.Error); err != nil {
			return nil, err
		}
		r.CreatedAt, r.UpdatedAt = parseTS(c), parseTS(u)
		if sent != "" {
			r.SentAt = parseTS(sent)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetMailLog returns one log row or ErrNotFound.
func (s *Store) GetMailLog(ctx context.Context, id string) (MailLogRow, error) {
	var r MailLogRow
	var c, u, sent string
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, recipient_domain, reference, status, attempts, created_at, updated_at, sent_at, error
		FROM mail_log WHERE id = ?`, id).Scan(&r.ID, &r.Kind, &r.RecipientDomain, &r.Reference, &r.Status, &r.Attempts, &c, &u, &sent, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.CreatedAt, r.UpdatedAt = parseTS(c), parseTS(u)
	if sent != "" {
		r.SentAt = parseTS(sent)
	}
	return r, nil
}

// PruneMailLog removes log rows older than t (the log is kept for a while
// for the settings page, not forever).
func (s *Store) PruneMailLog(ctx context.Context, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mail_log WHERE updated_at < ? AND id NOT IN (SELECT id FROM mail_queue)`, ts(t))
	return err
}
