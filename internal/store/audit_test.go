package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// appendLegacy writes an unkeyed row the way releases before the audit key
// did (plain SHA-256 chain, keyed = 0).
func appendLegacy(t *testing.T, s *Store, action string) AuditEvent {
	t.Helper()
	ctx := context.Background()
	var lastID int64
	lastHash := GenesisHash
	_ = s.db.QueryRowContext(ctx, `SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHash)
	e := AuditEvent{ID: lastID + 1, Time: s.now().Truncate(time.Microsecond), ActorName: "old", Action: action, Result: ResultOK, PrevHash: lastHash}
	e.Hash = chainHash(e)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO audit(id, ts, actor_sid, actor_name, action, target, detail, result, ip, user_agent, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, e.ID, ts(e.Time), e.ActorSID, e.ActorName, e.Action, e.Target, e.Detail,
		e.Result, e.IP, e.UserAgent, e.PrevHash, e.Hash); err != nil {
		t.Fatal(err)
	}
	return e
}

func mustAppend(t *testing.T, s *Store, action string) AuditEvent {
	t.Helper()
	e, err := s.AppendAudit(context.Background(), AuditEvent{ActorName: "lab.admin", Action: action, Result: ResultOK})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func dropTriggers(t *testing.T, s *Store) {
	t.Helper()
	for _, tr := range []string{"audit_no_update", "audit_no_delete"} {
		if _, err := s.db.Exec(`DROP TRIGGER ` + tr); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditAppendNeedsKey(t *testing.T) {
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.AppendAudit(context.Background(), AuditEvent{Action: "x"}); !errors.Is(err, ErrNoAuditKey) {
		t.Fatalf("append without a key: %v", err)
	}
	if err := s.SetAuditKey(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestAuditKeyStartsAfterLegacyRows(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	appendLegacy(t, s, "old.one")
	appendLegacy(t, s, "old.two")
	var sunk []AuditEvent
	s.SetAuditSink(func(e AuditEvent) { sunk = append(sunk, e) })
	e := mustAppend(t, s, "user.update")
	if e.ID != 4 || !e.Keyed {
		t.Fatalf("event %+v", e)
	}
	if len(sunk) != 2 || sunk[0].Action != AuditKeyStart || sunk[0].ID != 3 || sunk[1].ID != 4 {
		t.Fatalf("sink got %+v", sunk)
	}
	mustAppend(t, s, "user.update")
	res, err := s.VerifyAudit(ctx)
	if err != nil || res.BrokenAt != 0 || res.Rows != 5 || res.KeyedFrom != 3 || res.LastID != 5 {
		t.Fatalf("verify %+v %v", res, err)
	}
	// Without the key the keyed rows cannot be checked.
	s.auditMu.Lock()
	s.auditKey = nil
	s.auditMu.Unlock()
	if _, err := s.VerifyAudit(ctx); !errors.Is(err, ErrNoAuditKey) {
		t.Fatalf("verify without key: %v", err)
	}
}

func TestAuditNewChainHasNoMarker(t *testing.T) {
	s := openTest(t)
	e := mustAppend(t, s, "signin.password")
	if e.ID != 1 || e.Action != "signin.password" {
		t.Fatalf("first row %+v", e)
	}
	res, err := s.VerifyAudit(context.Background())
	if err != nil || res.BrokenAt != 0 || res.KeyedFrom != 1 {
		t.Fatalf("verify %+v %v", res, err)
	}
}

func TestAuditLegacyOnlyChainVerifies(t *testing.T) {
	s := openTest(t)
	appendLegacy(t, s, "a")
	appendLegacy(t, s, "b")
	res, err := s.VerifyAudit(context.Background())
	if err != nil || res.BrokenAt != 0 || res.Rows != 2 || res.KeyedFrom != 0 {
		t.Fatalf("verify %+v %v", res, err)
	}
}

func TestAuditTamperingDetected(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *Store {
		s := openTest(t)
		appendLegacy(t, s, "old")
		for range 4 {
			mustAppend(t, s, "user.update")
		}
		dropTriggers(t, s)
		return s
	}
	row := func(t *testing.T, s *Store, id int64) AuditEvent {
		rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit WHERE id = ?`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		rows.Next()
		e, err := scanAudit(rows)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	cases := []struct {
		name   string
		tamper func(t *testing.T, s *Store)
		broken int64
		reason string
	}{
		{"edit recomputed without the key", func(t *testing.T, s *Store) {
			e := row(t, s, 4)
			e.Result = ResultFailed
			_, _ = s.db.Exec(`UPDATE audit SET result = ?, hash = ? WHERE id = 4`, e.Result, chainHash(e))
		}, 4, "keyed hash"},
		{"edit under another key", func(t *testing.T, s *Store) {
			e := row(t, s, 4)
			e.Result = ResultFailed
			_, _ = s.db.Exec(`UPDATE audit SET result = ?, hash = ? WHERE id = 4`, e.Result, keyedHash(bytes.Repeat([]byte{1}, 32), e))
		}, 4, "keyed hash"},
		{"rows removed from the end", func(t *testing.T, s *Store) {
			_, _ = s.db.Exec(`DELETE FROM audit WHERE id >= 4`)
		}, 4, "removed from the end"},
		{"head anchor removed", func(t *testing.T, s *Store) {
			_, _ = s.db.Exec(`DELETE FROM audit_head`)
		}, 7, "missing"},
		{"head anchor forged", func(t *testing.T, s *Store) {
			_, _ = s.db.Exec(`UPDATE audit_head SET id = 3, hash = (SELECT hash FROM audit WHERE id = 3)`)
			_, _ = s.db.Exec(`DELETE FROM audit WHERE id > 3`)
		}, 4, "does not match"},
		{"unkeyed row appended", func(t *testing.T, s *Store) { appendLegacy(t, s, "late") }, 7, "unkeyed row after keyed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := setup(t)
			c.tamper(t, s)
			res, err := s.VerifyAudit(ctx)
			if err != nil || res.BrokenAt != c.broken || !strings.Contains(res.Reason, c.reason) {
				t.Fatalf("got %+v %v, want broken at %d (%q)", res, err, c.broken, c.reason)
			}
		})
	}
}

// TestAuditDowngradeLeavesHead: rewriting every keyed row as unkeyed still
// fails while the head anchor is there.
func TestAuditDowngradeLeavesHead(t *testing.T) {
	s := openTest(t)
	appendLegacy(t, s, "old")
	mustAppend(t, s, "user.update")
	dropTriggers(t, s)
	if _, err := s.db.Exec(`DELETE FROM audit WHERE id > 1`); err != nil {
		t.Fatal(err)
	}
	appendLegacy(t, s, "fake")
	res, err := s.VerifyAudit(context.Background())
	if err != nil || res.BrokenAt == 0 {
		t.Fatalf("downgrade not detected: %+v %v", res, err)
	}
}

// blockingWriter appends an audit row from inside the export's write: with
// the export holding the only connection, that append would wait forever.
type blockingWriter struct {
	s     *Store
	t     *testing.T
	wrote bool
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := w.s.AppendAudit(ctx, AuditEvent{Action: "during.export"}); err != nil {
			return 0, fmt.Errorf("append during export: %w", err)
		}
	}
	return len(p), nil
}

func TestAuditExportReleasesConnection(t *testing.T) {
	s := openTest(t)
	for range auditBatchSize + 10 {
		mustAppend(t, s, "user.update")
	}
	w := &blockingWriter{s: s, t: t}
	n, err := s.ExportAudit(context.Background(), AuditFilter{Action: "user."}, w)
	if err != nil || n != auditBatchSize+10 {
		t.Fatalf("export %d %v", n, err)
	}
	n, err = s.ExportAudit(context.Background(), AuditFilter{}, io.Discard)
	if err != nil || n != auditBatchSize+11 {
		t.Fatalf("full export %d %v", n, err)
	}
	if res, err := s.VerifyAudit(context.Background()); err != nil || res.BrokenAt != 0 || res.Rows != auditBatchSize+11 {
		t.Fatalf("verify %+v %v", res, err)
	}
}
