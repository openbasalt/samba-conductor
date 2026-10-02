package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// GenesisHash is the prev_hash of the first audit row.
var GenesisHash = strings.Repeat("0", 64)

// Results of audited actions.
const (
	ResultOK      = "ok"
	ResultDenied  = "denied"
	ResultFailed  = "failed"
	ResultPending = "pending"
)

// AuditEvent is one audit row.
type AuditEvent struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"ts"`
	ActorSID  string    `json:"actor_sid"`
	ActorName string    `json:"actor_name"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	// Detail is the preview (redacted LDIF, helper request) or a note.
	Detail    string `json:"detail"`
	Result    string `json:"result"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// chainHash is SHA-256 over the previous hash and the canonical JSON of
// every field but the hash itself (encoding/json writes struct fields in
// declaration order, so the encoding is deterministic).
func chainHash(e AuditEvent) string {
	c := e
	c.Hash = ""
	c.Time = e.Time.UTC()
	b, _ := json.Marshal(struct {
		ID        int64  `json:"id"`
		Time      string `json:"ts"`
		ActorSID  string `json:"actor_sid"`
		ActorName string `json:"actor_name"`
		Action    string `json:"action"`
		Target    string `json:"target"`
		Detail    string `json:"detail"`
		Result    string `json:"result"`
		IP        string `json:"ip"`
		UserAgent string `json:"user_agent"`
	}{c.ID, ts(c.Time), c.ActorSID, c.ActorName, c.Action, c.Target, c.Detail, c.Result, c.IP, c.UserAgent})
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{'\n'})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Limits keep one row bounded.
const (
	maxDetail = 16 << 10
	maxField  = 512
)

// AppendAudit adds an event at the end of the chain and returns it with
// its ID and hashes set.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) (AuditEvent, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	e.Time = s.now().Truncate(time.Microsecond)
	e.ActorSID, e.ActorName, e.Action = clip(e.ActorSID, maxField), clip(e.ActorName, maxField), clip(e.Action, 64)
	e.Target, e.Result, e.IP, e.UserAgent = clip(e.Target, maxField*2), clip(e.Result, maxField), clip(e.IP, 64), clip(e.UserAgent, 256)
	e.Detail = clip(e.Detail, maxDetail)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return e, err
	}
	defer func() { _ = tx.Rollback() }()
	var lastID int64
	var lastHash string
	err = tx.QueryRowContext(ctx, `SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		lastID, lastHash = 0, GenesisHash
	case err != nil:
		return e, err
	}
	e.ID = lastID + 1
	e.PrevHash = lastHash
	e.Hash = chainHash(e)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id, ts, actor_sid, actor_name, action, target, detail, result, ip, user_agent, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, e.ID, ts(e.Time), e.ActorSID, e.ActorName, e.Action, e.Target, e.Detail,
		e.Result, e.IP, e.UserAgent, e.PrevHash, e.Hash); err != nil {
		return e, err
	}
	return e, tx.Commit()
}

// AuditFilter narrows listings and exports. Empty fields match everything.
type AuditFilter struct {
	Actor  string // substring of actor name
	Action string // prefix of action
	Target string // substring of target
	Result string
	Since  time.Time
	Until  time.Time
}

func (f AuditFilter) where() (string, []any) {
	var conds []string
	var args []any
	if f.Actor != "" {
		conds = append(conds, `instr(lower(actor_name), lower(?)) > 0`)
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		conds = append(conds, `substr(action, 1, length(?)) = ?`)
		args = append(args, f.Action, f.Action)
	}
	if f.Target != "" {
		conds = append(conds, `instr(lower(target), lower(?)) > 0`)
		args = append(args, f.Target)
	}
	if f.Result != "" {
		conds = append(conds, `result = ?`)
		args = append(args, f.Result)
	}
	if !f.Since.IsZero() {
		conds = append(conds, `ts >= ?`)
		args = append(args, ts(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, `ts < ?`)
		args = append(args, ts(f.Until))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func scanAudit(rows *sql.Rows) (AuditEvent, error) {
	var e AuditEvent
	var t string
	err := rows.Scan(&e.ID, &t, &e.ActorSID, &e.ActorName, &e.Action, &e.Target, &e.Detail, &e.Result, &e.IP, &e.UserAgent, &e.PrevHash, &e.Hash)
	e.Time = parseTS(t)
	return e, err
}

const auditCols = `id, ts, actor_sid, actor_name, action, target, detail, result, ip, user_agent, prev_hash, hash`

// ListAudit returns events newest first, a window of the filtered log, and
// whether more follow.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter, offset, limit int) ([]AuditEvent, bool, error) {
	where, args := f.where()
	args = append(args, limit+1, offset)
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, e)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, rows.Err()
}

// ExportAudit writes the filtered events as JSON lines, oldest first.
func (s *Store) ExportAudit(ctx context.Context, f AuditFilter, w io.Writer) (int, error) {
	where, args := f.where()
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit`+where+` ORDER BY id ASC`, args...)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	enc := json.NewEncoder(w)
	n := 0
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return n, err
		}
		if err := enc.Encode(e); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// VerifyResult is the outcome of a chain check.
type VerifyResult struct {
	Rows     int
	LastHash string
	// BrokenAt is the first ID whose link or hash does not match (0 = intact).
	BrokenAt int64
	Reason   string
}

// VerifyAudit walks the whole chain from the genesis hash.
func (s *Store) VerifyAudit(ctx context.Context) (VerifyResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY id ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer func() { _ = rows.Close() }()
	res := VerifyResult{LastHash: GenesisHash}
	var expectID int64 = 1
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return res, err
		}
		switch {
		case e.ID != expectID:
			res.BrokenAt, res.Reason = expectID, fmt.Sprintf("row %d missing (found %d)", expectID, e.ID)
		case e.PrevHash != res.LastHash:
			res.BrokenAt, res.Reason = e.ID, "prev_hash does not match the previous row"
		case chainHash(e) != e.Hash:
			res.BrokenAt, res.Reason = e.ID, "row content does not match its hash"
		}
		if res.BrokenAt != 0 {
			return res, nil
		}
		res.Rows++
		res.LastHash = e.Hash
		expectID++
	}
	return res, rows.Err()
}
