package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenIsPrivateAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.db")
	ctx := context.Background()
	s, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %v %v", st.Mode().Perm(), err)
	}
	s, err = Open(ctx, p) // migrations already applied
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestSessions(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i, h := range []string{"a", "b", "c"} {
		sid := "S-1-5-21-1-2-3-1000"
		if i == 2 {
			sid = "S-1-5-21-1-2-3-1001"
		}
		if err := s.PutSession(ctx, SessionRow{IDHash: h, UserSID: sid, Username: "u", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IP: "10.0.0.1", UserAgent: "ua"}); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.UserSessions(ctx, "S-1-5-21-1-2-3-1000")
	if len(rows) != 2 {
		t.Fatalf("rows %d", len(rows))
	}
	gone, err := s.DeleteUserSessions(ctx, "S-1-5-21-1-2-3-1000")
	if err != nil || len(gone) != 2 {
		t.Fatalf("deleted %v %v", gone, err)
	}
	if err := s.DeleteAllSessions(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTOTPReplayAndRecovery(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	sid := "S-1-5-21-1-2-3-1105"
	if _, err := s.GetTOTP(ctx, sid); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
	if err := s.EnrollTOTP(ctx, TOTPRecord{UserSID: sid, Username: "lab.admin", Secret: []byte{1, 2}, LastStep: 100}, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UseTOTPStep(ctx, sid, 100); ok {
		t.Error("enrollment step replayed")
	}
	if ok, _ := s.UseTOTPStep(ctx, sid, 101); !ok {
		t.Error("new step refused")
	}
	if ok, _ := s.UseTOTPStep(ctx, sid, 101); ok {
		t.Error("same step accepted twice")
	}
	if ok, _ := s.UseTOTPStep(ctx, sid, 99); ok {
		t.Error("older step accepted")
	}
	if ok, _ := s.UseRecoveryCode(ctx, sid, "h1"); !ok {
		t.Error("recovery code refused")
	}
	if ok, _ := s.UseRecoveryCode(ctx, sid, "h1"); ok {
		t.Error("recovery code used twice")
	}
	if n, _ := s.RecoveryCodesLeft(ctx, sid); n != 1 {
		t.Errorf("left %d", n)
	}
	if err := s.DeleteTOTP(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, sid); n != 0 {
		t.Errorf("codes survived: %d", n)
	}
}

func TestEnrollLinks(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	s.SetClock(func() time.Time { return now })
	if err := s.CreateEnrollLink(ctx, "tok", "Lab.Admin", "setup", time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ValidEnrollLink(ctx, "tok", "other"); ok {
		t.Error("link valid for another user")
	}
	if ok, _ := s.ValidEnrollLink(ctx, "tok", "lab.admin"); !ok {
		t.Error("link not valid")
	}
	now = now.Add(2 * time.Hour)
	if ok, _ := s.ConsumeEnrollLink(ctx, "tok", "lab.admin"); ok {
		t.Error("expired link consumed")
	}
	now = now.Add(-2 * time.Hour)
	if ok, _ := s.ConsumeEnrollLink(ctx, "tok", "lab.admin"); !ok {
		t.Error("link not consumed")
	}
	if ok, _ := s.ConsumeEnrollLink(ctx, "tok", "lab.admin"); ok {
		t.Error("link consumed twice")
	}
}

func TestAuditChain(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := range 5 {
		e, err := s.AppendAudit(ctx, AuditEvent{ActorSID: "S-1-5-21-1", ActorName: "lab.admin", Action: "user.update",
			Target: "CN=x" + string(rune('a'+i)), Detail: "dn: x\nchangetype: modify", Result: ResultOK, IP: "10.0.0.1", UserAgent: "test"})
		if err != nil || e.ID != int64(i+1) {
			t.Fatalf("append %d: %+v %v", i, e, err)
		}
	}
	res, err := s.VerifyAudit(ctx)
	if err != nil || res.Rows != 5 || res.BrokenAt != 0 {
		t.Fatalf("verify %+v %v", res, err)
	}
	// The table refuses updates and deletes.
	if _, err := s.db.ExecContext(ctx, `UPDATE audit SET result = 'ok' WHERE id = 2`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update allowed: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE id = 5`); err == nil {
		t.Fatal("delete allowed")
	}
	evs, more, err := s.ListAudit(ctx, AuditFilter{Target: "cn=xb"}, 0, 10)
	if err != nil || more || len(evs) != 1 || evs[0].ID != 2 {
		t.Fatalf("filter: %+v %v %v", evs, more, err)
	}
	var buf bytes.Buffer
	n, err := s.ExportAudit(ctx, AuditFilter{Action: "user."}, &buf)
	if err != nil || n != 5 {
		t.Fatalf("export %d %v", n, err)
	}
	sc := bufio.NewScanner(&buf)
	sc.Scan()
	var first AuditEvent
	if err := json.Unmarshal(sc.Bytes(), &first); err != nil || first.ID != 1 || first.PrevHash != GenesisHash {
		t.Fatalf("first exported %+v %v", first, err)
	}
	// Someone with file access bypasses the triggers and edits a row: the
	// chain check finds it.
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE audit SET result = 'failed' WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	res, _ = s.VerifyAudit(ctx)
	if res.BrokenAt != 3 {
		t.Fatalf("tampering not detected: %+v", res)
	}
	// Recomputing that row's hash breaks the next link instead.
	e3 := AuditEvent{}
	rows, _ := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit WHERE id = 3`)
	rows.Next()
	e3, _ = scanAudit(rows)
	_ = rows.Close()
	if _, err := s.db.ExecContext(ctx, `UPDATE audit SET hash = ? WHERE id = 3`, chainHash(e3)); err != nil {
		t.Fatal(err)
	}
	res, _ = s.VerifyAudit(ctx)
	if res.BrokenAt != 4 {
		t.Fatalf("re-hashed row not detected: %+v", res)
	}
}
