package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// fakeSync answers conductor-sync's management API from memory.
type fakeSync struct {
	mu      sync.Mutex
	calls   []syncapi.Request
	status  syncapi.Status
	cfg     syncapi.ConfigView
	detail  syncapi.RunDetail
	job     syncapi.Job
	updated *syncapi.ConfigUpdateParams
	key     string
	fail    map[syncapi.Op]*syncapi.Error
}

func newFakeSync(now time.Time) *fakeSync {
	digest := strings.Repeat("ab", 32)
	return &fakeSync{
		status: syncapi.Status{Version: "test", Mode: "apply", Connector: "google", Ready: true, Scheduler: "timer", ScheduleInterval: "15m0s",
			FirstManualApply: "run 3", Audit: syncapi.AuditState{Intact: true, Rows: 42},
			Key:         &syncapi.KeyInfo{ClientEmail: "sync@project.iam.gserviceaccount.com", KeyID: "k1", Source: "database"},
			LastRun:     &syncapi.Run{ID: 7, Action: "apply", Trigger: "scheduled", Status: "blocked", StartedAt: now.Add(-time.Hour)},
			OpenBlocked: []syncapi.Run{{ID: 7, Action: "apply", Trigger: "scheduled", Status: "blocked", StartedAt: now.Add(-time.Hour), Violations: []syncapi.Violation{{Limit: "max_suspends", Value: 500, Max: 10}}}}},
		cfg: syncapi.ConfigView{Version: 2, Settings: syncapi.Settings{Mode: "apply",
			Scope:   syncapi.ScopeSettings{UserBases: []string{"OU=People,DC=lab,DC=test"}, IncludeGroups: []string{"S-1-5-21-1-2-3-1500"}},
			Mapping: syncapi.MappingSettings{PrimaryEmail: []string{"{sAMAccountName}@example.com"}, AllowedDomains: []string{"example.com"}, DefaultOrgUnit: "/"},
			Google:  syncapi.GoogleSettings{AdminSubject: "admin@example.com", Customer: "my_customer", MemberRole: "MEMBER"},
			Limits:  syncapi.LimitSettings{MaxCreates: 50, MaxSuspends: 10}, Schedule: syncapi.ScheduleSettings{Interval: "15m0s"}},
			Host: syncapi.HostInfo{ConfigPath: "/etc/conductor-sync/conductor-sync.toml", Realm: "LAB.TEST", BindUser: "svc.sync"}},
		detail: syncapi.RunDetail{Run: syncapi.Run{ID: 7, Action: "apply", Trigger: "scheduled", Status: "blocked", StartedAt: now.Add(-time.Hour),
			Violations: []syncapi.Violation{{Limit: "max_suspends", Value: 500, Max: 10}}}, HasPlan: true, Digest: digest,
			Counts: map[string]int{"user.suspend": 500}, Sections: map[string]int{"suspend": 500}, Writes: 500, ManagedUsers: 2500,
			Limits:     []syncapi.LimitRow{{Limit: "max_suspends", Value: 500, Max: 10, Exceeded: true}},
			Ops:        []syncapi.PlanOp{{Seq: 0, Kind: "user.suspend", Key: "user0003@example.com", Reason: "no longer in the sync scope"}},
			Applicable: true, Override: true, Confirmation: syncapi.Confirmation(digest, true),
			Groups: []syncapi.ScopeGroup{{Role: "exclude", Ref: "S-1-5-21-1-2-3-1600", Found: true, Name: "Support", Members: 500}}},
		job: syncapi.Job{ID: "job-0000000001", Kind: "apply", State: syncapi.JobRunning, RunID: 8, Actor: "conductor:lab.admin",
			Progress: syncapi.Progress{Total: 500, Done: 120}},
		fail: map[syncapi.Op]*syncapi.Error{},
	}
}

func (f *fakeSync) Call(_ context.Context, req syncapi.Request) (syncapi.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := req.Decode()
	if err != nil {
		return syncapi.Response{}, err
	}
	f.calls = append(f.calls, req)
	if e := f.fail[req.Op]; e != nil {
		return syncapi.ErrorResponse(req.ID, e), e
	}
	var out any
	switch req.Op {
	case syncapi.OpStatus:
		out = f.status
	case syncapi.OpConfigGet:
		out = f.cfg
	case syncapi.OpRunsList:
		out = syncapi.RunsList{Runs: []syncapi.Run{f.detail.Run}, Total: 1}
	case syncapi.OpRunGet:
		out = f.detail
	case syncapi.OpJobGet:
		out = f.job
	case syncapi.OpPlanStart, syncapi.OpApplyStart:
		out = syncapi.JobStarted{Job: f.job}
	case syncapi.OpConfigHistory:
		out = []syncapi.ConfigVersion{{ID: 2, Actor: "conductor:lab.admin", Origin: "api", Changes: []syncapi.Change{{Path: "mode", Old: "dry-run", New: "apply"}}}}
	case syncapi.OpConfigExport:
		out = syncapi.ConfigExport{TOML: "mode = \"apply\"\n"}
	case syncapi.OpConfigValidate:
		vp := p.(*syncapi.ConfigValidateParams)
		out = syncapi.ConfigValidateResult{Valid: true, Changes: syncapi.DiffSettings(f.cfg.Settings, vp.Settings)}
	case syncapi.OpConfigUpdate:
		up := *p.(*syncapi.ConfigUpdateParams)
		f.updated = &up
		out = syncapi.ConfigUpdateResult{Version: f.cfg.Version + 1, Changes: syncapi.DiffSettings(f.cfg.Settings, up.Settings)}
	case syncapi.OpKeySet:
		f.key = p.(*syncapi.KeySetParams).KeyJSON
		out = syncapi.KeyInfo{ClientEmail: "new@project.iam.gserviceaccount.com", KeyID: "k2", Source: "database"}
	case syncapi.OpConnectionTest:
		out = syncapi.TestResult{AD: syncapi.Check{OK: true, Detail: "connected to dc1"}, Google: syncapi.Check{OK: true, Detail: "token issued"}}
	case syncapi.OpMappingPreview:
		out = syncapi.PreviewResult{Users: []syncapi.PreviewUser{{Account: "jdoe", InScope: true, Email: "jdoe@example.com", OrgUnit: "/", Placement: "default"}}}
	default:
		return syncapi.Response{}, &syncapi.Error{Code: syncapi.CodeBadRequest, Message: "unexpected"}
	}
	return syncapi.OKResponse(req.ID, out)
}

func (f *fakeSync) last(op syncapi.Op) *syncapi.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].Op == op {
			return &f.calls[i]
		}
	}
	return nil
}

func (f *fakeSync) count(op syncapi.Op) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.Op == op {
			n++
		}
	}
	return n
}

func syncHarness(t *testing.T) (*harness, *fakeSync) {
	h := newHarness(t)
	fs := newFakeSync(h.now)
	h.s.sync = fs
	return h, fs
}

func TestSyncOverviewAndAccess(t *testing.T) {
	h, fs := syncHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("GET", "/admin/sync", admin, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, want := range []string{`data-e2e="sync-alert-blocked-7"`, `data-e2e="sync-btn-plan"`, `data-e2e="sync-btn-mode-dry-run"`,
		"sync@project.iam.gserviceaccount.com", `data-e2e="nav-link-sync"`, `data-e2e="sync-text-audit"`} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	// The read is made as the signed-in administrator.
	if r := fs.last(syncapi.OpStatus); r == nil || r.Actor.User != "lab.admin" || r.Actor.IP == "" {
		t.Fatalf("actor %+v", r)
	}
	// Dashboard card.
	if body := h.do("GET", "/admin", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="dashboard-card-sync"`) {
		t.Log("dashboard needs AD (fake backend); card checked through syncDashboard below")
	}
	if st, ok := h.s.syncDashboard(context.Background(), &reqCtx{s: h.s, sess: h.s.sess.get(context.Background(), admin), ip: "192.0.2.10"}); !ok || st.LastRun.ID != 7 {
		t.Fatalf("dashboard status %+v", st)
	}
	// Auditors and helpdesk never reach the section.
	for _, who := range []string{"auditor.user", "helpdesk.user"} {
		tok := h.session(t, who, stageFull, true)
		for _, p := range []string{"/admin/sync", "/admin/sync/runs", "/admin/sync/runs/7", "/admin/sync/config", "/admin/sync/setup"} {
			if w := h.do("GET", p, tok, nil); w.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d", who, p, w.Code)
			}
		}
		if body := h.do("GET", "/me", tok, nil).Body.String(); strings.Contains(body, "nav-link-sync") {
			t.Errorf("%s sees the sync navigation", who)
		}
	}
	// Disabled: a hint, no navigation entry.
	h.s.sync = nil
	body = h.do("GET", "/admin/sync", admin, nil).Body.String()
	if !strings.Contains(body, "sync-card-disabled") || strings.Contains(body, `data-e2e="nav-link-sync"`) {
		t.Fatal("disabled view")
	}
	// Unreachable API: an error, not a crash.
	h.s.sync = fs
	fs.fail[syncapi.OpStatus] = &syncapi.Error{Code: syncapi.CodeUnavailable, Message: "dial unix: no such file"}
	if body := h.do("GET", "/admin/sync", admin, nil).Body.String(); !strings.Contains(body, "form-text-error") || strings.Contains(body, "no such file") {
		t.Fatal("unavailable view")
	}
}

func TestSyncApplyNeedsTypedConfirmationAndReauth(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	page := h.do("GET", "/admin/sync/runs/7", admin, nil).Body.String()
	for _, want := range []string{`data-e2e="sync-run-alert-blocked"`, `data-e2e="sync-run-form-apply"`, fs.detail.Confirmation,
		`data-e2e="sync-run-limit-exceeded-max-suspends"`, "user0003@example.com", `data-e2e="sync-run-tab-suspend"`, "Support"} {
		if !strings.Contains(page, want) {
			t.Errorf("run page lacks %q", want)
		}
	}
	// Wrong confirmation: refused, audited, nothing started.
	w := h.do("POST", "/admin/sync/runs/7/apply", admin, url.Values{"digest": {fs.detail.Digest}, "confirm": {"apply " + fs.detail.Digest[:8]}})
	if w.Header().Get("Location") != "/admin/sync/runs/7" || fs.count(syncapi.OpApplyStart) != 0 {
		t.Fatalf("wrong confirmation: %d %q", w.Code, w.Header().Get("Location"))
	}
	// A stale digest: refused.
	w = h.do("POST", "/admin/sync/runs/7/apply", admin, url.Values{"digest": {strings.Repeat("0", 64)}, "confirm": {fs.detail.Confirmation}})
	if fs.count(syncapi.OpApplyStart) != 0 || w.Header().Get("Location") != "/admin/sync/runs/7" {
		t.Fatal("stale digest accepted")
	}
	// Right confirmation: a preview with re-authentication.
	w = h.do("POST", "/admin/sync/runs/7/apply", admin, url.Values{"digest": {fs.detail.Digest}, "confirm": {fs.detail.Confirmation}})
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %d %q", w.Code, loc)
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "override_limits: true") || !strings.Contains(cp, fs.detail.Digest) || !strings.Contains(cp, "confirm-text-reauth") || !strings.Contains(cp, "confirm-text-warning") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized || fs.count(syncapi.OpApplyStart) != 0 {
		t.Fatalf("without the second factor: %d", w.Code)
	}
	w = h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if w.Header().Get("Location") != "/admin/sync/jobs/job-0000000001" {
		t.Fatalf("after confirm: %d %q", w.Code, w.Header().Get("Location"))
	}
	r := fs.last(syncapi.OpApplyStart)
	var ap syncapi.ApplyStartParams
	_ = json.Unmarshal(r.Params, &ap)
	if ap.RunID != 7 || ap.Digest != fs.detail.Digest || !ap.OverrideLimits || r.Actor.User != "lab.admin" {
		t.Fatalf("apply params %+v", ap)
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "sync.apply_override"}, 0, 10)
	if len(evs) != 2 || evs[0].Result != store.ResultOK || !strings.Contains(evs[0].Detail, "[re-authenticated]") {
		t.Fatalf("audit %+v", evs)
	}
	// The job page follows the run and refreshes; done -> the run page.
	jp := h.do("GET", "/admin/sync/jobs/job-0000000001", admin, nil).Body.String()
	if !strings.Contains(jp, `http-equiv="refresh"`) || !strings.Contains(jp, "120 of 500") {
		t.Fatalf("job page:\n%s", jp)
	}
	fs.job.State, fs.job.RunStatus = syncapi.JobDone, "applied"
	if w := h.do("GET", "/admin/sync/jobs/job-0000000001", admin, nil); w.Header().Get("Location") != "/admin/sync/runs/8" {
		t.Fatalf("job done: %q", w.Header().Get("Location"))
	}
	// A run that stopped at the limits also lands on its run page.
	fs.job.RunStatus, fs.job.Error = "blocked", "plan exceeds the safety limits; nothing applied"
	if w := h.do("GET", "/admin/sync/jobs/job-0000000001", admin, nil); w.Header().Get("Location") != "/admin/sync/runs/8" {
		t.Fatalf("job blocked: %q", w.Header().Get("Location"))
	}
	if body := h.do("GET", "/admin/sync", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="flash-error"`) {
		t.Fatal("blocked outcome not flagged")
	}
	// A job that failed before recording a run shows its error.
	fs.job.State, fs.job.RunID, fs.job.RunStatus, fs.job.Error = syncapi.JobFailed, 0, "", "another conductor-sync run is in progress"
	if body := h.do("GET", "/admin/sync/jobs/job-0000000001", admin, nil).Body.String(); !strings.Contains(body, "another conductor-sync run is in progress") {
		t.Fatal("job error not shown")
	}
}

func TestSyncPlanAndRunNow(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if w := h.do("POST", "/admin/sync/plan", admin, nil); w.Header().Get("Location") != "/admin/sync/jobs/job-0000000001" || fs.count(syncapi.OpPlanStart) != 1 {
		t.Fatalf("plan: %q", w.Header().Get("Location"))
	}
	fs.fail[syncapi.OpPlanStart] = &syncapi.Error{Code: syncapi.CodeBusy, Message: "a plan is already running"}
	if w := h.do("POST", "/admin/sync/plan", admin, nil); w.Header().Get("Location") != "/admin/sync" {
		t.Fatal("busy not handled")
	}
	w := h.do("POST", "/admin/sync/run-now", admin, nil)
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") || fs.count(syncapi.OpApplyStart) != 0 {
		t.Fatal("run now without confirmation")
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	var ap syncapi.ApplyStartParams
	if r := fs.last(syncapi.OpApplyStart); r == nil || json.Unmarshal(r.Params, &ap) != nil || !ap.Scheduled {
		t.Fatal("run now params")
	}
}

func TestSyncModeSwitch(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("POST", "/admin/sync/mode", admin, url.Values{"mode": {"dry-run"}})
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("mode: %q", loc)
	}
	if !strings.Contains(h.do("GET", loc, admin, nil).Body.String(), "mode: apply -&gt; dry-run") {
		t.Fatal("mode preview")
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if fs.updated == nil || fs.updated.Settings.Mode != "dry-run" || fs.updated.BaseVersion != 2 || len(fs.updated.Settings.Scope.IncludeGroups) != 1 {
		t.Fatalf("update %+v", fs.updated)
	}
	if w := h.do("POST", "/admin/sync/mode", admin, url.Values{"mode": {"yolo"}}); w.Code != http.StatusBadRequest {
		t.Fatal("bad mode accepted")
	}
}

// postMultipart sends a key upload.
func (h *harness) postMultipart(t *testing.T, path, tok, field, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf", h.csrfOf(tok))
	fw, _ := mw.CreateFormFile(field, filename)
	_, _ = fw.Write(content)
	_ = mw.Close()
	r := httptest.NewRequest("POST", "https://"+testHost+path, &buf)
	r.RemoteAddr = "192.0.2.10:40000"
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	return w
}

func TestSyncKeyUpload(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if w := h.postMultipart(t, "/admin/sync/setup/key", admin, "key", "k.json", []byte(`{"type":"user"}`)); w.Header().Get("Location") != "/admin/sync/setup?step=google" {
		t.Fatalf("invalid key: %q", w.Header().Get("Location"))
	}
	key := []byte(`{"type":"service_account","client_email":"new@project.iam.gserviceaccount.com","private_key_id":"k2","private_key":"-----BEGIN PRIVATE KEY-----\nSECRETMATERIAL\n-----END PRIVATE KEY-----\n"}`)
	w := h.postMultipart(t, "/admin/sync/setup/key", admin, "key", "k.json", key)
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %d %q", w.Code, loc)
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "new@project.iam.gserviceaccount.com") || strings.Contains(cp, "SECRETMATERIAL") {
		t.Fatal("confirm page shows the key or misses its identity")
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if fs.key != string(key) {
		t.Fatal("key not sent")
	}
	var audit bytes.Buffer
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{}, 0, 100)
	for _, e := range evs {
		audit.WriteString(e.Detail)
	}
	if strings.Contains(audit.String(), "SECRETMATERIAL") || !strings.Contains(audit.String(), "client_email: new@project") {
		t.Fatal("audit leaks the key or lacks its identity")
	}
}

func TestSyncSetupDraftAndSave(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	step := func(path string, form url.Values) string {
		t.Helper()
		w := h.do("POST", path, admin, form)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Header().Get("Location")
	}
	if loc := step("/admin/sync/setup/google", url.Values{"admin_subject": {"sync-admin@example.com"}, "domains": {"Example.com, corp.example.com"}, "go": {"next"}}); loc != "/admin/sync/setup?step=scope" {
		t.Fatalf("next step %q", loc)
	}
	step("/admin/sync/setup/scope", url.Values{"action": {"exclude"}, "ref": {"S-1-5-21-1-2-3-1600"}})
	step("/admin/sync/setup/scope", url.Values{"action": {"add_base"}, "dn": {"OU=Contractors,DC=lab,DC=test"}})
	if loc := step("/admin/sync/setup/scope", url.Values{"action": {"include"}, "ref": {"not a group; rm -rf"}}); loc != "/admin/sync/setup?step=scope" {
		t.Fatal("bad group")
	}
	step("/admin/sync/setup/mapping", url.Values{"action": {"add_group_rule"}, "ref": {"S-1-5-21-1-2-3-1700"}, "target": {"/Finance"}, "priority": {"10"}})
	step("/admin/sync/setup/mapping", url.Values{"action": {"add_group_rule"}, "ref": {"S-1-5-21-1-2-3-1701"}, "target": {"Finance"}, "priority": {"0"}})
	step("/admin/sync/setup/templates", url.Values{"primary_email": {"{mail|lower}\n{sAMAccountName|lower}@example.com\n"}, "given_name": {"{givenName}"},
		"family_name": {"{sn}"}, "attr_title": {"{title}"}, "go": {"preview"}, "q": {"jdoe"}})
	if r := fs.last(syncapi.OpMappingPreview); r == nil || !strings.Contains(string(r.Params), `"query":"jdoe"`) || !strings.Contains(string(r.Params), "S-1-5-21-1-2-3-1700") {
		t.Fatal("preview not made with the draft")
	}
	if body := h.do("GET", "/admin/sync/setup?step=templates", admin, nil).Body.String(); !strings.Contains(body, "sync-setup-preview-email-jdoe") {
		t.Fatal("preview not shown")
	}
	step("/admin/sync/setup/safety", url.Values{"max_creates": {"100"}, "max_suspends": {"5"}, "max_unsuspends": {"50"}, "max_renames": {"10"},
		"max_updates": {"500"}, "max_group_changes": {"20"}, "max_membership_changes": {"1000"}, "max_touched_percent": {"12.5"},
		"min_source_users": {"1"}, "max_source_drop_percent": {"10"}, "suspend_disabled": {"1"}, "adopt": {"never"}, "interval": {"30m"}})
	review := h.do("GET", "/admin/sync/setup?step=review", admin, nil).Body.String()
	if !strings.Contains(review, "sync-setup-review-changes") || !strings.Contains(review, "google.admin_subject") {
		t.Fatalf("review:\n%s", review)
	}
	loc := step("/admin/sync/setup/save", url.Values{"comment": {"finance placement"}})
	if !strings.HasPrefix(loc, "/confirm/") || fs.updated != nil {
		t.Fatalf("save: %q", loc)
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	u := fs.updated
	if u == nil || u.BaseVersion != 2 || u.Comment != "finance placement" {
		t.Fatalf("update %+v", u)
	}
	s := u.Settings
	if s.Google.AdminSubject != "sync-admin@example.com" || fmt.Sprint(s.Mapping.AllowedDomains) != "[example.com corp.example.com]" ||
		fmt.Sprint(s.Scope.ExcludeGroups) != "[S-1-5-21-1-2-3-1600]" || len(s.Scope.UserBases) != 2 || len(s.Mapping.OrgUnits) != 1 ||
		s.Mapping.OrgUnits[0].Priority != 10 || len(s.Mapping.PrimaryEmail) != 2 || s.Mapping.Attributes["title"] != "{title}" ||
		s.Limits.MaxTouchedPercent != 12.5 || s.Schedule.Interval != "30m" {
		t.Fatalf("saved settings %+v", s)
	}
	// The draft is gone after the save.
	sess := h.s.sess.get(context.Background(), admin)
	if sess.syncDraft != nil {
		t.Fatal("draft kept")
	}
}

func TestSyncConfigAndExport(t *testing.T) {
	h, _ := syncHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	body := h.do("GET", "/admin/sync/config", admin, nil).Body.String()
	if !strings.Contains(body, `data-e2e="sync-config-history-2"`) || !strings.Contains(body, "/etc/conductor-sync/conductor-sync.toml") {
		t.Fatal("config page")
	}
	w := h.do("GET", "/admin/sync/config/export", admin, nil)
	if !strings.Contains(w.Header().Get("Content-Disposition"), "conductor-sync-") || w.Body.String() != "mode = \"apply\"\n" {
		t.Fatalf("export %q", w.Body.String())
	}
}
