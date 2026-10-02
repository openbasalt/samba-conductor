package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- WebAuthn credentials ----

// WebAuthnCredential is a stored security key of a user.
type WebAuthnCredential struct {
	ID         string // base64url credential ID
	UserSID    string
	Username   string
	Name       string
	Data       []byte // go-webauthn Credential as JSON
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// AddWebAuthnCredential stores a newly registered credential.
func (s *Store) AddWebAuthnCredential(ctx context.Context, c WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_credentials(cred_id, user_sid, username, name, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserSID, c.Username, clip(c.Name, 64), c.Data, ts(s.now()))
	return err
}

// WebAuthnCredentials lists a user's credentials, oldest first.
func (s *Store) WebAuthnCredentials(ctx context.Context, userSID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cred_id, user_sid, username, name, data, created_at, COALESCE(last_used_at, '')
		FROM webauthn_credentials WHERE user_sid = ? ORDER BY created_at, cred_id`, userSID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var created, used string
		if err := rows.Scan(&c.ID, &c.UserSID, &c.Username, &c.Name, &c.Data, &created, &used); err != nil {
			return nil, err
		}
		c.CreatedAt, c.LastUsedAt = parseTS(created), parseTS(used)
		out = append(out, c)
	}
	return out, rows.Err()
}

// UseWebAuthnCredential records a successful assertion (new counter and
// flags in data).
func (s *Store) UseWebAuthnCredential(ctx context.Context, userSID, id string, data []byte) error {
	res, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET data = ?, last_used_at = ? WHERE cred_id = ? AND user_sid = ?`,
		data, ts(s.now()), id, userSID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebAuthnCredential removes one credential of a user.
func (s *Store) DeleteWebAuthnCredential(ctx context.Context, userSID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE cred_id = ? AND user_sid = ?`, id, userSID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebAuthnCredentials removes every credential of a user (2FA reset).
func (s *Store) DeleteWebAuthnCredentials(ctx context.Context, userSID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE user_sid = ?`, userSID)
	return err
}

// ---- bulk jobs ----

// Bulk job and row states.
const (
	JobPreviewed   = "previewed"
	JobRunning     = "running"
	JobDone        = "done"
	JobCancelled   = "cancelled"
	JobInterrupted = "interrupted"

	RowPending = "pending"
	RowOK      = "ok"
	RowFailed  = "failed"
	RowSkipped = "skipped"
)

// BulkJob is a stored job.
type BulkJob struct {
	ID         string
	Kind       string
	OwnerSID   string
	OwnerName  string
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time
	Status     string
	Total      int
}

// BulkRow is one row of a job.
type BulkRow struct {
	No      int
	Label   string
	Target  string
	Input   string
	Preview string
	Status  string
	Error   string
}

// CreateBulkJob stores a previewed job and its rows.
func (s *Store) CreateBulkJob(ctx context.Context, j BulkJob, rows []BulkRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO bulk_jobs(id, kind, owner_sid, owner_name, created_at, status, total) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		j.ID, j.Kind, j.OwnerSID, j.OwnerName, ts(s.now()), JobPreviewed, len(rows)); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO bulk_rows(job_id, row_no, label, target, input, preview, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			j.ID, r.No, clip(r.Label, 256), r.Target, r.Input, r.Preview, RowPending); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetBulkJobStatus moves a job to a new state (start and finish times are
// set with it).
func (s *Store) SetBulkJobStatus(ctx context.Context, id, status string) error {
	now := ts(s.now())
	var err error
	switch status {
	case JobRunning:
		_, err = s.db.ExecContext(ctx, `UPDATE bulk_jobs SET status = ?, started_at = ? WHERE id = ?`, status, now, id)
	case JobDone, JobCancelled, JobInterrupted:
		_, err = s.db.ExecContext(ctx, `UPDATE bulk_jobs SET status = ?, finished_at = ? WHERE id = ?`, status, now, id)
	default:
		_, err = s.db.ExecContext(ctx, `UPDATE bulk_jobs SET status = ? WHERE id = ?`, status, id)
	}
	return err
}

// SetBulkRowResult records the outcome of one row.
func (s *Store) SetBulkRowResult(ctx context.Context, jobID string, no int, status, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE bulk_rows SET status = ?, error = ? WHERE job_id = ? AND row_no = ?`, status, clip(errMsg, 512), jobID, no)
	return err
}

// GetBulkJob reads a job.
func (s *Store) GetBulkJob(ctx context.Context, id string) (BulkJob, error) {
	var j BulkJob
	var c, st, fi string
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, owner_sid, owner_name, created_at, COALESCE(started_at, ''), COALESCE(finished_at, ''), status, total
		FROM bulk_jobs WHERE id = ?`, id).Scan(&j.ID, &j.Kind, &j.OwnerSID, &j.OwnerName, &c, &st, &fi, &j.Status, &j.Total)
	if errors.Is(err, sql.ErrNoRows) {
		return j, ErrNotFound
	}
	j.CreatedAt, j.StartedAt, j.FinishedAt = parseTS(c), parseTS(st), parseTS(fi)
	return j, err
}

// BulkRows lists the rows of a job in order.
func (s *Store) BulkRows(ctx context.Context, jobID string) ([]BulkRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT row_no, label, target, input, preview, status, error FROM bulk_rows WHERE job_id = ? ORDER BY row_no`, jobID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []BulkRow
	for rows.Next() {
		var r BulkRow
		if err := rows.Scan(&r.No, &r.Label, &r.Target, &r.Input, &r.Preview, &r.Status, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListBulkJobs lists a user's jobs (all users when ownerSID is ""), newest
// first.
func (s *Store) ListBulkJobs(ctx context.Context, ownerSID string, limit int) ([]BulkJob, error) {
	q := `SELECT id, kind, owner_sid, owner_name, created_at, COALESCE(started_at, ''), COALESCE(finished_at, ''), status, total FROM bulk_jobs`
	args := []any{}
	if ownerSID != "" {
		q += ` WHERE owner_sid = ?`
		args = append(args, ownerSID)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []BulkJob
	for rows.Next() {
		var j BulkJob
		var c, st, fi string
		if err := rows.Scan(&j.ID, &j.Kind, &j.OwnerSID, &j.OwnerName, &c, &st, &fi, &j.Status, &j.Total); err != nil {
			return nil, err
		}
		j.CreatedAt, j.StartedAt, j.FinishedAt = parseTS(c), parseTS(st), parseTS(fi)
		out = append(out, j)
	}
	return out, rows.Err()
}

// InterruptBulkJobs marks jobs left running by a previous process (their
// remaining rows were never attempted) and returns how many there were.
func (s *Store) InterruptBulkJobs(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE bulk_jobs SET status = ?, finished_at = ? WHERE status = ?`, JobInterrupted, ts(s.now()), JobRunning)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RowCounts counts a job's rows per status.
func (s *Store) RowCounts(ctx context.Context, jobID string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM bulk_rows WHERE job_id = ? GROUP BY status`, jobID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
