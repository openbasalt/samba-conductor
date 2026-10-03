package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor/internal/store"
	"github.com/samba-conductor/conductor/internal/totp"
)

// fakeHelper answers the backup operations from memory and records calls.
type fakeHelper struct {
	mu     sync.Mutex
	st     helper.BackupStatus
	calls  []helper.Request
	policy *helper.BackupPolicy
}

func (f *fakeHelper) Call(_ context.Context, req helper.Request) (helper.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := req.Decode()
	if err != nil {
		return helper.Response{}, err
	}
	f.calls = append(f.calls, req)
	switch req.Op {
	case helper.OpBackupStatus:
		st := f.st
		if f.policy != nil {
			st.Policy, st.PolicyCustom = *f.policy, true
		}
		return helper.OKResponse(req.ID, st)
	case helper.OpBackupTrigger:
		return helper.OKResponse(req.ID, helper.BackupTriggerResult{RequestID: "backup-1"})
	case helper.OpBackupPolicySet:
		pol := *p.(*helper.BackupPolicy)
		f.policy = &pol
		return helper.OKResponse(req.ID, struct{}{})
	}
	return helper.Response{}, &helper.Error{Code: helper.CodeNotAllowed, Message: "no"}
}

func (f *fakeHelper) last(op helper.OpName) *helper.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].Op == op {
			return &f.calls[i]
		}
	}
	return nil
}

func sampleStatus(now time.Time) helper.BackupStatus {
	return helper.BackupStatus{Configured: true, Realm: "LAB.TEST", DC: "dc1", LastRunAt: now.Add(-10 * time.Minute), NextDueAt: now.Add(14 * time.Hour),
		Policy: helper.DefaultBackupPolicy(), Recipients: []string{"SHA256:0011223344556677"}, SigningKeyID: "abcdef0123456789",
		Destinations: []helper.BackupDestination{{Name: "minio", Type: "s3", Location: "10.93.0.1:9093/conductor-lab/"}},
		Backups: []helper.BackupRecord{{ID: "20261002T023000Z-dc1", CreatedAt: now.Add(-9 * time.Hour), Trigger: "scheduled", Status: helper.StatusOK,
			Size: 8_600_000, Users: 2531, DurationMS: 45000, Uploads: []helper.UploadRecord{{Destination: "minio", Status: helper.StatusOK, VerifiedAt: now.Add(-9 * time.Hour)}}}},
		Drills: []helper.DrillRecord{{ID: "20261002T030000Z-drill", BackupID: "20261002T023000Z-dc1", Host: "drill", StartedAt: now.Add(-8 * time.Hour),
			FinishedAt: now.Add(-8*time.Hour + 2*time.Minute), Passed: true, RTOMS: 95_000, Checks: []helper.DrillCheck{{Name: "ldap", OK: true}}}}}
}

// enrollTOTP gives a user a TOTP secret (for re-authentication).
func (h *harness) enrollTOTP(t *testing.T, sam string) []byte {
	t.Helper()
	secret := []byte("12345678901234567890")
	u, _ := sid.MustParse(testDomain).WithRID(userRIDs[sam])
	sealed, err := h.s.box.Seal(secret, []byte(u.String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.EnrollTOTP(context.Background(), store.TOTPRecord{UserSID: u.String(), Username: sam, Secret: sealed, LastStep: 0}, nil); err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestBackupsPage(t *testing.T) {
	h := newHarness(t)
	fh := &fakeHelper{st: sampleStatus(h.now)}
	h.s.helper = fh
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("GET", "/admin/backups", admin, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, want := range []string{`data-e2e="backups-row-20261002t023000z-dc1"`, `data-e2e="backups-btn-run"`, `data-e2e="backups-btn-drill"`,
		`data-e2e="drills-badge-passed"`, "1 min 35 s", "8.6 MB", "SHA256:0011223344556677", `data-e2e="nav-link-backups"`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}
	if strings.Contains(body, "backups-alert-") {
		t.Error("alert shown for a healthy status")
	}
	// The read is attributed to the user.
	if r := fh.last(helper.OpBackupStatus); r == nil || r.Caller.User != "lab.admin" {
		t.Fatalf("caller %+v", r)
	}
	// Auditor: read-only.
	aud := h.session(t, "auditor.user", stageFull, true)
	body = h.do("GET", "/admin/backups", aud, nil).Body.String()
	if !strings.Contains(body, `backups-row-20261002t023000z-dc1`) || strings.Contains(body, "backups-btn-run") || strings.Contains(body, "backups-link-config") {
		t.Fatal("auditor view")
	}
	for _, p := range []string{"/admin/backups/run", "/admin/backups/drill", "/admin/backups/config"} {
		if w := h.do("POST", p, aud, nil); w.Code != http.StatusForbidden {
			t.Errorf("auditor POST %s: %d", p, w.Code)
		}
	}
	// Helpdesk: nothing.
	hd := h.session(t, "helpdesk.user", stageFull, true)
	if w := h.do("GET", "/admin/backups", hd, nil); w.Code != http.StatusForbidden {
		t.Fatalf("helpdesk: %d", w.Code)
	}
	// Not configured.
	fh.st = helper.BackupStatus{}
	if body := h.do("GET", "/admin/backups", admin, nil).Body.String(); !strings.Contains(body, "backups-card-unconfigured") {
		t.Fatal("unconfigured view")
	}
	// Helper down.
	h.s.helper = nil
	if body := h.do("GET", "/admin/backups", admin, nil).Body.String(); !strings.Contains(body, "form-text-error") {
		t.Fatal("helper error not shown")
	}
}

func TestBackupNowNeedsReauth(t *testing.T) {
	h := newHarness(t)
	fh := &fakeHelper{st: sampleStatus(h.now)}
	h.s.helper = fh
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("POST", "/admin/backups/run", admin, nil)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %d %q", w.Code, loc)
	}
	page := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(page, "backup.trigger") || !strings.Contains(page, "action: backup") || !strings.Contains(page, `confirm-text-reauth`) {
		t.Fatalf("confirm page:\n%s", page)
	}
	// Without re-authentication nothing is requested.
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", w.Code)
	}
	if fh.last(helper.OpBackupTrigger) != nil {
		t.Fatal("triggered without re-authentication")
	}
	code := totp.Code(secret, totp.Step(h.now))
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {code}}); w.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	r := fh.last(helper.OpBackupTrigger)
	if r == nil || r.Caller.User != "lab.admin" || !strings.Contains(string(r.Params), `"backup"`) {
		t.Fatalf("trigger %+v", r)
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "backup.request_backup"}, 0, 10)
	if len(evs) != 2 || evs[0].Result != store.ResultOK || !strings.Contains(evs[0].Detail, "[re-authenticated]") {
		t.Fatalf("audit %+v", evs)
	}
}

func TestBackupPolicyEdit(t *testing.T) {
	h := newHarness(t)
	fh := &fakeHelper{st: sampleStatus(h.now)}
	h.s.helper = fh
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if body := h.do("GET", "/admin/backups/config", admin, nil).Body.String(); !strings.Contains(body, `value="02:30"`) {
		t.Fatal("form not pre-filled")
	}
	form := url.Values{"time": {"03:15"}, "every": {"24"}, "daily": {"10"}, "weekly": {"4"}, "monthly": {"12"}, "max_age": {"26"}, "drill": {"7"}}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("max_age", "12") // below the 24 h interval
	if w := h.do("POST", "/admin/backups/config", admin, bad); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "form-text-error") {
		t.Fatalf("invalid policy: %d", w.Code)
	}
	w := h.do("POST", "/admin/backups/config", admin, form)
	loc := w.Header().Get("Location")
	page := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(page, "schedule.time (UTC): 02:30 -&gt; 03:15") || !strings.Contains(page, "retention.daily: 7 -&gt; 10") || strings.Contains(page, "weekly:") {
		t.Fatalf("preview:\n%s", page)
	}
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}}); w.Code != http.StatusSeeOther {
		t.Fatalf("confirm %d", w.Code)
	}
	if fh.policy == nil || fh.policy.Schedule.Time != "03:15" || fh.policy.Retention.Daily != 10 {
		t.Fatalf("policy %+v", fh.policy)
	}
	// The same values again: nothing to change.
	if w := h.do("POST", "/admin/backups/config", admin, form); w.Header().Get("Location") != "/admin/backups" {
		t.Fatalf("no change: %q", w.Header().Get("Location"))
	}
}

func TestBackupBannerAndIngestion(t *testing.T) {
	h := newHarness(t)
	st := sampleStatus(h.now)
	st.Drills[0].Passed = false
	st.Drills[0].Checks = []helper.DrillCheck{{Name: "kerberos", OK: false, Detail: "refused"}}
	st.Alerts = []helper.BackupAlert{{Kind: helper.AlertDrillFailed, Detail: "failed checks: kerberos"}}
	h.s.helper = &fakeHelper{st: st}
	ctx := context.Background()
	h.s.pollBackups(ctx)
	h.s.pollBackups(ctx) // results are recorded once
	evs, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "backup.drill_result"}, 0, 10)
	if len(evs) != 1 || evs[0].Result != store.ResultFailed || evs[0].ActorName != "drill:drill" {
		t.Fatalf("drill audit %+v", evs)
	}
	evs, _, _ = h.st.ListAudit(ctx, store.AuditFilter{Action: "backup.result"}, 0, 10)
	if len(evs) != 1 || evs[0].Target != "20261002T023000Z-dc1" || evs[0].ActorName != "conductor-backup" {
		t.Fatalf("backup audit %+v", evs)
	}
	if rs, _ := h.st.BackupResults(ctx, "drill", 10); len(rs) != 1 || rs[0].Result != "failed" {
		t.Fatalf("results %+v", rs)
	}
	// The banner lists the alert plus a stale backup the status lagged
	// behind (27 hours later, the scheduler stopped).
	h.now = h.now.Add(27 * time.Hour)
	rc := &reqCtx{s: h.s, lang: "en"}
	alerts := h.s.backupAlerts(rc, st)
	kinds := map[string]bool{}
	for _, a := range alerts {
		kinds[a.Kind] = true
	}
	if !kinds[helper.AlertDrillFailed] || !kinds[helper.AlertStale] || !kinds[helper.AlertScheduler] {
		t.Fatalf("alerts %+v", alerts)
	}
}
