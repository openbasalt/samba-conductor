package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// FileServer is an enrolled conductor-files agent.
type FileServer struct {
	ID           string
	Name         string
	Address      string
	AgentPin     string
	EnrolledAt   time.Time
	EnrolledBy   string
	AgentVersion string
}

// AddFileServer records an enrollment.
func (s *Store) AddFileServer(ctx context.Context, f FileServer) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO file_servers(id, name, address, agent_pin, enrolled_at, enrolled_by, agent_version)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, f.ID, clip(f.Name, 253), clip(f.Address, 260), f.AgentPin, ts(f.EnrolledAt), clip(f.EnrolledBy, 256), clip(f.AgentVersion, 64))
	return err
}

// FileServers lists the enrolled servers by name.
func (s *Store) FileServers(ctx context.Context) ([]FileServer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, address, agent_pin, enrolled_at, enrolled_by, agent_version FROM file_servers ORDER BY name, address`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []FileServer
	for rows.Next() {
		f, err := scanFileServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanFileServer(r scanner) (FileServer, error) {
	var f FileServer
	var at string
	if err := r.Scan(&f.ID, &f.Name, &f.Address, &f.AgentPin, &at, &f.EnrolledBy, &f.AgentVersion); err != nil {
		return f, err
	}
	f.EnrolledAt = parseTS(at)
	return f, nil
}

// FileServer returns one enrolled server.
func (s *Store) FileServer(ctx context.Context, id string) (FileServer, error) {
	f, err := scanFileServer(s.db.QueryRowContext(ctx, `SELECT id, name, address, agent_pin, enrolled_at, enrolled_by, agent_version FROM file_servers WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

// RemoveFileServer forgets a server (and its pinned key).
func (s *Store) RemoveFileServer(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM file_servers WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
