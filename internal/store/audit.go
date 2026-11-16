package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
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
	// Keyed: the hash is an HMAC under the audit key (false for rows
	// written before the key existed).
	Keyed bool `json:"keyed"`
}

// canonicalAudit is the canonical JSON of every field of a row but its
// hashes and keyed flag (encoding/json writes struct fields in declaration
// order, so the encoding is deterministic).
func canonicalAudit(e AuditEvent) []byte {
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
	}{e.ID, ts(e.Time.UTC()), e.ActorSID, e.ActorName, e.Action, e.Target, e.Detail, e.Result, e.IP, e.UserAgent})
	return b
}

// chainHash is the unkeyed hash of rows written before the audit key
// existed: SHA-256 over the previous hash and the canonical JSON.
func chainHash(e AuditEvent) string {
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{'\n'})
	h.Write(canonicalAudit(e))
	return hex.EncodeToString(h.Sum(nil))
}

// Limits keep one row bounded.
const (
	maxDetail = 16 << 10
	maxField  = 512
)

// Audit keying. Rows are chained with HMAC-SHA256 under a key the
// database does not hold (a root-only file, given to the service as a
// systemd credential), so whoever can rewrite the database but cannot read
// the key cannot recompute the chain. Rows from before the key existed keep
// their plain SHA-256 hash; the first keyed row after them is an
// AuditKeyStart marker, and no unkeyed row may follow a keyed one. The head
// anchor (audit_head) keeps the newest row's id and hash under the key, so
// rows removed from the end are detected too.

// AuditKeyStart is the action of the marker row where keying starts.
const AuditKeyStart = "audit.key_start"

// MinAuditKeyLen is the shortest audit key accepted (bytes).
const MinAuditKeyLen = 32

// ErrNoAuditKey is returned by appends and checks of keyed rows when no
// audit key was set.
var ErrNoAuditKey = errors.New("store: no audit key (the audit chain is keyed; see [audit] key_file)")

// SetAuditKey sets the key of the audit chain (at least MinAuditKeyLen
// bytes). The store keeps its own copy.
func (s *Store) SetAuditKey(key []byte) error {
	if len(key) < MinAuditKeyLen {
		return fmt.Errorf("store: the audit key must have at least %d bytes", MinAuditKeyLen)
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.auditKey = append([]byte(nil), key...)
	return nil
}

// SetAuditSink sets a function that receives every appended row after it
// is committed (a copy of the log outside the database, e.g. the journal).
// It must not call back into the store.
func (s *Store) SetAuditSink(fn func(AuditEvent)) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.auditSink = fn
}

// keyedHash is HMAC-SHA256 under the audit key over the same input as
// chainHash, with its own domain prefix.
func keyedHash(key []byte, e AuditEvent) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("conductor-audit-row-v1\n"))
	m.Write([]byte(e.PrevHash))
	m.Write([]byte{'\n'})
	m.Write(canonicalAudit(e))
	return hex.EncodeToString(m.Sum(nil))
}

// headMAC authenticates the head anchor (the newest row's id and hash).
func headMAC(key []byte, id int64, hash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("conductor-audit-head-v1\n" + strconv.FormatInt(id, 10) + "\n" + hash))
	return hex.EncodeToString(m.Sum(nil))
}

// AppendAudit adds an event at the end of the chain and returns it with
// its ID and hashes set. The chain must be keyed (SetAuditKey): when the
// newest row is from before the key, an AuditKeyStart marker row comes
// first.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) (AuditEvent, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if len(s.auditKey) == 0 {
		return e, ErrNoAuditKey
	}
	now := s.now().Truncate(time.Microsecond)
	e.Time = now
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
	var lastKeyed bool
	err = tx.QueryRowContext(ctx, `SELECT id, hash, keyed FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHash, &lastKeyed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		lastID, lastHash, lastKeyed = 0, GenesisHash, true // a new chain is keyed from its first row
	case err != nil:
		return e, err
	}
	insert := func(r *AuditEvent) error {
		r.ID, r.PrevHash, r.Keyed = lastID+1, lastHash, true
		r.Hash = keyedHash(s.auditKey, *r)
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id, ts, actor_sid, actor_name, action, target, detail, result, ip, user_agent, prev_hash, hash, keyed)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`, r.ID, ts(r.Time), r.ActorSID, r.ActorName, r.Action, r.Target, r.Detail,
			r.Result, r.IP, r.UserAgent, r.PrevHash, r.Hash); err != nil {
			return err
		}
		lastID, lastHash = r.ID, r.Hash
		return nil
	}
	var written []AuditEvent
	if !lastKeyed {
		marker := AuditEvent{Time: now, ActorName: "conductor", Action: AuditKeyStart, Result: ResultOK,
			Detail: fmt.Sprintf("rows from this one on are keyed (HMAC-SHA256 under the audit key); rows 1 to %d are plain SHA-256", lastID)}
		if err := insert(&marker); err != nil {
			return e, err
		}
		written = append(written, marker)
	}
	if err := insert(&e); err != nil {
		return e, err
	}
	written = append(written, e)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_head(singleton, id, hash, mac) VALUES (1, ?, ?, ?)
		ON CONFLICT(singleton) DO UPDATE SET id = excluded.id, hash = excluded.hash, mac = excluded.mac`,
		e.ID, e.Hash, headMAC(s.auditKey, e.ID, e.Hash)); err != nil {
		return e, err
	}
	if err := tx.Commit(); err != nil {
		return e, err
	}
	if s.auditSink != nil {
		for _, w := range written {
			s.auditSink(w)
		}
	}
	return e, nil
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
	err := rows.Scan(&e.ID, &t, &e.ActorSID, &e.ActorName, &e.Action, &e.Target, &e.Detail, &e.Result, &e.IP, &e.UserAgent, &e.PrevHash, &e.Hash, &e.Keyed)
	e.Time = parseTS(t)
	return e, err
}

const auditCols = `id, ts, actor_sid, actor_name, action, target, detail, result, ip, user_agent, prev_hash, hash, keyed`

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

// auditBatch is the next window of at most n filtered rows with an id
// above after, oldest first. The query's rows are closed before it
// returns, so the database connection is free while the caller writes
// them out.
func (s *Store) auditBatch(ctx context.Context, f AuditFilter, after int64, n int) ([]AuditEvent, error) {
	where, args := f.where()
	if where == "" {
		where = " WHERE id > ?"
	} else {
		where += " AND id > ?"
	}
	args = append(args, after, n)
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit`+where+` ORDER BY id ASC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]AuditEvent, 0, n)
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// auditBatchSize bounds the rows an export or a check holds in memory
// (a row is at most about 18 KiB).
const auditBatchSize = 256

// ExportAudit writes the filtered events as JSON lines, oldest first. It
// reads a batch, releases the database, then writes the batch: SQLite has
// one connection here, and a slow reader of the export must not hold it.
func (s *Store) ExportAudit(ctx context.Context, f AuditFilter, w io.Writer) (int, error) {
	enc := json.NewEncoder(w)
	n := 0
	var after int64
	for {
		batch, err := s.auditBatch(ctx, f, after, auditBatchSize)
		if err != nil {
			return n, err
		}
		for _, e := range batch {
			if err := enc.Encode(e); err != nil {
				return n, err
			}
			n++
		}
		if len(batch) < auditBatchSize {
			return n, nil
		}
		after = batch[len(batch)-1].ID
	}
}

// VerifyResult is the outcome of a chain check.
type VerifyResult struct {
	Rows     int
	LastID   int64
	LastHash string
	// KeyedFrom is the first keyed row (0: none; rows before it are plain
	// SHA-256).
	KeyedFrom int64
	// BrokenAt is the first ID whose link or hash does not match, or the
	// first missing one (0 = intact).
	BrokenAt int64
	Reason   string
}

// auditHead reads the head anchor (ok false when there is none).
func (s *Store) auditHead(ctx context.Context) (id int64, hash, mac string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT id, hash, mac FROM audit_head WHERE singleton = 1`).Scan(&id, &hash, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", false, nil
	}
	return id, hash, mac, err == nil, err
}

// VerifyAudit walks the whole chain from the genesis hash: every link, the
// plain hash of rows from before the key, the HMAC of keyed rows (no
// unkeyed row after a keyed one), and the head anchor, which must name the
// last row (rows removed from the end break it). Keyed rows need the audit
// key (ErrNoAuditKey otherwise).
func (s *Store) VerifyAudit(ctx context.Context) (VerifyResult, error) {
	s.auditMu.Lock()
	key := s.auditKey
	s.auditMu.Unlock()
	res := VerifyResult{LastHash: GenesisHash}
	var expectID int64 = 1
	for {
		batch, err := s.auditBatch(ctx, AuditFilter{}, res.LastID, auditBatchSize)
		if err != nil {
			return res, err
		}
		for _, e := range batch {
			if e.Keyed && len(key) == 0 {
				return res, ErrNoAuditKey
			}
			switch {
			case e.ID != expectID:
				res.BrokenAt, res.Reason = expectID, fmt.Sprintf("row %d missing (found %d)", expectID, e.ID)
			case e.PrevHash != res.LastHash:
				res.BrokenAt, res.Reason = e.ID, "prev_hash does not match the previous row"
			case !e.Keyed && res.KeyedFrom != 0:
				res.BrokenAt, res.Reason = e.ID, fmt.Sprintf("unkeyed row after keyed rows (keyed from row %d)", res.KeyedFrom)
			case e.Keyed && res.KeyedFrom == 0 && e.ID != 1 && e.Action != AuditKeyStart:
				res.BrokenAt, res.Reason = e.ID, "the first keyed row after unkeyed rows is not the "+AuditKeyStart+" marker"
			case !e.Keyed && chainHash(e) != e.Hash:
				res.BrokenAt, res.Reason = e.ID, "row content does not match its hash"
			case e.Keyed && !hmac.Equal([]byte(keyedHash(key, e)), []byte(e.Hash)):
				res.BrokenAt, res.Reason = e.ID, "row content does not match its keyed hash (edited, or another audit key)"
			}
			if res.BrokenAt != 0 {
				return res, nil
			}
			if e.Keyed && res.KeyedFrom == 0 {
				res.KeyedFrom = e.ID
			}
			res.Rows++
			res.LastID, res.LastHash = e.ID, e.Hash
			expectID++
		}
		if len(batch) < auditBatchSize {
			break
		}
	}
	hid, hhash, storedMAC, ok, err := s.auditHead(ctx)
	if err != nil {
		return res, err
	}
	switch {
	case !ok && res.KeyedFrom == 0:
		// A chain from before the key: nothing anchors its end.
	case !ok:
		res.BrokenAt, res.Reason = res.LastID+1, "the head anchor is missing"
	case len(key) == 0:
		return res, ErrNoAuditKey
	case !hmac.Equal([]byte(headMAC(key, hid, hhash)), []byte(storedMAC)):
		res.BrokenAt, res.Reason = res.LastID+1, "the head anchor does not match the audit key"
	case hid > res.LastID:
		res.BrokenAt, res.Reason = res.LastID+1, fmt.Sprintf("the chain ends at row %d but the head anchor names row %d: rows were removed from the end", res.LastID, hid)
	case hid < res.LastID:
		res.BrokenAt, res.Reason = hid+1, fmt.Sprintf("rows %d to %d were added without updating the head anchor", hid+1, res.LastID)
	case hhash != res.LastHash:
		res.BrokenAt, res.Reason = hid, "the head anchor names another hash for the last row"
	}
	return res, nil
}
