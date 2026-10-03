package store

import (
	"context"
	"time"
)

// BackupResult is a backup run or a restore drill as conductor recorded it.
type BackupResult struct {
	Kind   string // "backup" or "drill"
	ID     string
	At     time.Time
	Result string
	Detail string // JSON summary
}

// RecordBackupResult stores a result the first time it is seen and reports
// whether it was new.
func (s *Store) RecordBackupResult(ctx context.Context, r BackupResult) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO backup_results(kind, id, at, result, detail, seen_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(kind, id) DO NOTHING`, r.Kind, clip(r.ID, 128), ts(r.At), clip(r.Result, 16), clip(r.Detail, maxDetail), ts(s.now()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// BackupResults lists recorded results of a kind, newest first.
func (s *Store) BackupResults(ctx context.Context, kind string, limit int) ([]BackupResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, id, at, result, detail FROM backup_results WHERE kind = ? ORDER BY at DESC LIMIT ?`, kind, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []BackupResult
	for rows.Next() {
		var r BackupResult
		var at string
		if err := rows.Scan(&r.Kind, &r.ID, &at, &r.Result, &r.Detail); err != nil {
			return nil, err
		}
		r.At = parseTS(at)
		out = append(out, r)
	}
	return out, rows.Err()
}
