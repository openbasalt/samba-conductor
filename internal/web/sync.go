package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Google Workspace sync (P5b). conductor never talks to Google: it drives
// conductor-sync (its own user and sandbox) through conductor-sync's local
// management API, always as the signed-in administrator. Reads need
// PermSyncRead, changes PermSyncWrite (administrators only); every change
// that touches the configuration, the key or Google is previewed and
// confirmed with a fresh second factor, and is audited here and in
// conductor-sync's own hash-chained log.

// SyncClient calls conductor-sync's management API.
type SyncClient interface {
	Call(ctx context.Context, req syncapi.Request) (syncapi.Response, error)
}

var errSyncDisabled = errors.New("web: the Google Workspace sync section is not enabled ([sync] in conductor.toml)")

// syncCache keeps the last status for the dashboard card (one API call
// per 30 s at most).
type syncCache struct {
	mu sync.Mutex
	st *syncapi.Status
	at time.Time
}

// syncActor identifies the signed-in user to conductor-sync.
func syncActor(rc *reqCtx) syncapi.Actor {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	return syncapi.Actor{User: rc.sess.sam, SID: rc.sess.userSID.String(), Session: rc.sess.hash[:16], IP: rc.ip}
}

// syncCall runs one API operation as the signed-in user. out must be a
// fresh value (results are decoded into it).
func (s *Server) syncCall(ctx context.Context, rc *reqCtx, op syncapi.Op, params syncapi.Params, out any) error {
	if s.sync == nil {
		return errSyncDisabled
	}
	req, err := syncapi.NewRequest(newToken()[:24], op, syncActor(rc), params)
	if err != nil {
		return err
	}
	resp, err := s.sync.Call(ctx, req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return syncapi.DecodeResult(resp, out)
}

// syncErr renders an API error for the user: a translated sentence, plus
// conductor-sync's own detail (validation messages, the reason a plan
// cannot be applied) where it helps.
func (s *Server) syncErr(rc *reqCtx, err error) string { return s.syncErrT(rc.T, err) }

func (s *Server) syncErrT(t func(string, ...any) string, err error) string {
	var e *syncapi.Error
	switch {
	case errors.Is(err, errSyncDisabled):
		return t("sync.err.disabled")
	case errors.As(err, &e):
		msg := t("sync.err." + string(e.Code))
		if strings.HasPrefix(msg, "[") {
			msg = t("sync.err.failed")
		}
		detail := e.Message
		if len(e.Details) > 0 {
			detail = strings.Join(e.Details, "; ")
		}
		if e.Code == syncapi.CodeUnavailable {
			return msg
		}
		return msg + " " + detail
	case errors.Is(err, context.DeadlineExceeded):
		return t("sync.err.unavailable")
	}
	s.log.Warn("sync API call failed", "err", err)
	return t("sync.err.failed")
}

func syncTimeout(rc *reqCtx) (context.Context, context.CancelFunc) {
	return context.WithTimeout(rc.ctx(), requestTimeout)
}

// ---- overview ----

func (s *Server) handleSync(rc *reqCtx) {
	d := map[string]any{"CanWrite": rc.roles.Has(PermSyncWrite)}
	if s.sync == nil {
		d["Disabled"] = true
		rc.render(http.StatusOK, "sync", d)
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var st syncapi.Status
	if err := s.syncCall(ctx, rc, syncapi.OpStatus, nil, &st); err != nil {
		d["Error"] = s.syncErr(rc, err)
		rc.render(http.StatusOK, "sync", d)
		return
	}
	s.syncStatus.set(&st, s.now())
	d["S"] = st
	var runs syncapi.RunsList
	if err := s.syncCall(ctx, rc, syncapi.OpRunsList, syncapi.RunsListParams{Limit: 8}, &runs); err == nil {
		d["Runs"] = runs.Runs
	}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err == nil {
		d["Cfg"] = cfg
	}
	rc.render(http.StatusOK, "sync", d)
}

func (c *syncCache) set(st *syncapi.Status, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st, c.at = st, at
}

// syncDashboard returns the status for the dashboard card (cached 30 s).
func (s *Server) syncDashboard(ctx context.Context, rc *reqCtx) (*syncapi.Status, bool) {
	s.syncStatus.mu.Lock()
	st, at := s.syncStatus.st, s.syncStatus.at
	s.syncStatus.mu.Unlock()
	if st != nil && s.now().Sub(at) < 30*time.Second {
		return st, true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var fresh syncapi.Status
	if err := s.syncCall(ctx, rc, syncapi.OpStatus, nil, &fresh); err != nil {
		return nil, false
	}
	s.syncStatus.set(&fresh, s.now())
	return &fresh, true
}

// ---- plan, run now, jobs ----

func (s *Server) handleSyncPlan(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var js syncapi.JobStarted
	if err := s.syncCall(ctx, rc, syncapi.OpPlanStart, nil, &js); err != nil {
		s.audit(ctx, rc, "sync.plan", "google", s.syncErr(rc, err), store.ResultFailed)
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync")
		return
	}
	s.audit(ctx, rc, "sync.plan", "google", "job "+js.Job.ID, store.ResultOK)
	rc.redirect("/admin/sync/jobs/" + js.Job.ID)
}

func (s *Server) handleSyncRunNow(rc *reqCtx) {
	preview := fmt.Sprintf("conductor-sync %s\nscheduled: true\n# %s", syncapi.OpApplyStart, rc.T("sync.runnow.preview"))
	p := &pendingOp{perm: PermSyncWrite, action: "sync.run_now", target: "google", reauth: true,
		title: rc.T("sync.runnow.title"), summary: rc.T("sync.runnow.summary"), preview: preview,
		back: "/admin/sync", done: rc.T("sync.job.started")}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var js syncapi.JobStarted
		if err := s.syncCall(ctx, rc, syncapi.OpApplyStart, syncapi.ApplyStartParams{Scheduled: true}, &js); err != nil {
			return err
		}
		p.back = "/admin/sync/jobs/" + js.Job.ID
		return nil
	}
	rc.propose(p)
}

func (s *Server) handleSyncJob(rc *reqCtx) {
	id := rc.r.PathValue("id")
	if len(id) < 8 || len(id) > 64 {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var j syncapi.Job
	if err := s.syncCall(ctx, rc, syncapi.OpJobGet, syncapi.JobGetParams{ID: id}, &j); err != nil {
		if syncapi.ErrorCodeOf(err) == syncapi.CodeNotFound {
			rc.errorPage(http.StatusNotFound, "sync.job.gone")
			return
		}
		rc.render(http.StatusOK, "sync_job", map[string]any{"Error": s.syncErr(rc, err)})
		return
	}
	if j.State != syncapi.JobRunning && j.RunID != 0 && j.RunStatus != "" {
		// Finished: the run page tells the outcome (applied, blocked at
		// the limits, partial...).
		kind := "ok"
		switch j.RunStatus {
		case syncapi.StatusApplied, syncapi.StatusPlanned, syncapi.StatusNothing:
		default:
			kind = "error"
		}
		rc.sess.addFlash(kind, rc.T("sync.job.finished", j.RunID, rc.T("sync.status."+j.RunStatus)))
		rc.redirect(fmt.Sprintf("/admin/sync/runs/%d", j.RunID))
		return
	}
	d := map[string]any{"J": j, "Refresh": j.State == syncapi.JobRunning}
	if j.Progress.Total > 0 {
		d["Percent"] = 100 * (j.Progress.Done + j.Progress.Failed + j.Progress.Skipped) / j.Progress.Total
	}
	rc.render(http.StatusOK, "sync_job", d)
}

// ---- runs ----

var syncStatuses = []string{syncapi.StatusBlocked, syncapi.StatusApplied, syncapi.StatusPartial, syncapi.StatusFailed,
	syncapi.StatusPlanned, syncapi.StatusDryRun, syncapi.StatusNothing, syncapi.StatusInterrupted, syncapi.StatusRunning}

func (s *Server) handleSyncRuns(rc *reqCtx) {
	status := rc.r.URL.Query().Get("status")
	if !slices.Contains(syncStatuses, status) {
		status = ""
	}
	page := rc.pageParam()
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var list syncapi.RunsList
	d := map[string]any{"Status": status, "Statuses": syncStatuses, "Page": page}
	if err := s.syncCall(ctx, rc, syncapi.OpRunsList, syncapi.RunsListParams{Status: status, Limit: pageSize, Offset: (page - 1) * pageSize}, &list); err != nil {
		d["Error"] = s.syncErr(rc, err)
	} else {
		d["Runs"], d["Total"], d["More"] = list.Runs, list.Total, page*pageSize < list.Total
	}
	rc.render(http.StatusOK, "sync_runs", d)
}

// syncOpsPage is the page size of operation lists.
const syncOpsPage = 100

func runIDParam(rc *reqCtx) (int64, bool) {
	id, err := strconv.ParseInt(rc.r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) handleSyncRun(rc *reqCtx) {
	id, ok := runIDParam(rc)
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	q := rc.r.URL.Query()
	section := q.Get("section")
	if section != "" && !slices.Contains(syncapi.Sections, section) {
		section = ""
	}
	failed := q.Get("failed") == "1"
	page := rc.pageParam()
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	// First read: the counts per section, to pick the default section.
	var det syncapi.RunDetail
	params := syncapi.RunGetParams{ID: id, Section: section, Offset: (page - 1) * syncOpsPage, Limit: syncOpsPage, FailedOnly: failed}
	if err := s.syncCall(ctx, rc, syncapi.OpRunGet, params, &det); err != nil {
		if syncapi.ErrorCodeOf(err) == syncapi.CodeNotFound {
			rc.errorPage(http.StatusNotFound, "err.not_found")
			return
		}
		rc.render(http.StatusOK, "sync_run", map[string]any{"Error": s.syncErr(rc, err)})
		return
	}
	if section == "" && !failed {
		for _, sec := range syncapi.Sections {
			if det.Sections[sec] > 0 {
				section = sec
				break
			}
		}
		if section != "" {
			params.Section = section
			det = syncapi.RunDetail{}
			if err := s.syncCall(ctx, rc, syncapi.OpRunGet, params, &det); err != nil {
				rc.render(http.StatusOK, "sync_run", map[string]any{"Error": s.syncErr(rc, err)})
				return
			}
		}
	}
	type sectionTab struct {
		Key   string
		Count int
	}
	var tabs []sectionTab
	for _, sec := range syncapi.Sections {
		if det.Sections[sec] > 0 {
			tabs = append(tabs, sectionTab{sec, det.Sections[sec]})
		}
	}
	rc.render(http.StatusOK, "sync_run", map[string]any{"R": det, "Section": section, "Tabs": tabs, "Failed": failed,
		"Page": page, "More": page*syncOpsPage < det.OpsMatching, "CanWrite": rc.roles.Has(PermSyncWrite),
		"Short": shortDigest(det.Digest)})
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// handleSyncRunApply checks the typed confirmation against a fresh read of
// the plan, then proposes the apply (re-authentication required). The API
// applies only if the fresh plan still has the reviewed digest.
func (s *Server) handleSyncRunApply(rc *reqCtx) {
	id, ok := runIDParam(rc)
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	back := fmt.Sprintf("/admin/sync/runs/%d", id)
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var det syncapi.RunDetail
	if err := s.syncCall(ctx, rc, syncapi.OpRunGet, syncapi.RunGetParams{ID: id, Limit: 1}, &det); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(back)
		return
	}
	switch {
	case !det.Applicable:
		rc.flashErr("sync.apply.not_applicable")
		rc.redirect(back)
		return
	case rc.form("digest") != det.Digest:
		rc.flashErr("sync.apply.changed")
		rc.redirect(back)
		return
	case rc.form("confirm") != det.Confirmation:
		s.audit(ctx, rc, "sync.apply", back, "typed confirmation did not match", store.ResultDenied)
		rc.flashErr("sync.apply.confirm_mismatch", det.Confirmation)
		rc.redirect(back)
		return
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("conductor-sync %s", syncapi.OpApplyStart), fmt.Sprintf("run: %d", id),
		"digest: "+det.Digest, fmt.Sprintf("override_limits: %v", det.Override))
	for _, sec := range syncapi.Sections {
		if n := det.Sections[sec]; n > 0 {
			lines = append(lines, fmt.Sprintf("# %s: %d", rc.T("sync.section."+sec), n))
		}
	}
	warning := ""
	action := "sync.apply"
	if det.Override {
		action = "sync.apply_override"
		var vs []string
		for _, l := range det.Limits {
			if l.Exceeded {
				vs = append(vs, fmt.Sprintf("%s: %g > %g", rc.T("sync.limit."+l.Limit), l.Value, l.Max))
			}
		}
		warning = rc.T("sync.apply.override_warning", strings.Join(vs, "; "))
	}
	p := &pendingOp{perm: PermSyncWrite, action: action, target: fmt.Sprintf("run %d", id), reauth: true,
		title: rc.T("sync.apply.title", id), summary: rc.T("sync.apply.summary", det.Writes), warning: warning,
		preview: strings.Join(lines, "\n"), back: back, done: rc.T("sync.job.started")}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var js syncapi.JobStarted
		err := s.syncCall(ctx, rc, syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: id, Digest: det.Digest, OverrideLimits: det.Override}, &js)
		if err != nil {
			return err
		}
		p.back = "/admin/sync/jobs/" + js.Job.ID
		return nil
	}
	rc.propose(p)
}

// ---- mode ----

func (s *Server) handleSyncMode(rc *reqCtx) {
	mode := rc.form("mode")
	if mode != "apply" && mode != "dry-run" {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync")
		return
	}
	if cfg.Settings.Mode == mode {
		rc.flashOK("form.no_change")
		rc.redirect("/admin/sync")
		return
	}
	next := cfg.Settings
	next.Mode = mode
	preview := fmt.Sprintf("conductor-sync %s\nbase_version: %d\nmode: %s -> %s\n# %s", syncapi.OpConfigUpdate, cfg.Version,
		cfg.Settings.Mode, mode, rc.T("sync.mode.preview_"+strings.ReplaceAll(mode, "-", "_")))
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.mode", target: "google", reauth: true,
		title: rc.T("sync.mode.title"), summary: rc.T("sync.mode.summary", mode), preview: preview,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.syncCall(ctx, rc, syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: cfg.Version, Settings: next,
				Comment: "mode " + mode + " (conductor)"}, &syncapi.ConfigUpdateResult{})
		},
		back: "/admin/sync", done: rc.T("sync.mode.done", mode)})
}

// ---- configuration view and export ----

func (s *Server) handleSyncConfig(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSyncWrite)}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		d["Error"] = s.syncErr(rc, err)
		rc.render(http.StatusOK, "sync_config", d)
		return
	}
	d["C"] = cfg
	var hist []syncapi.ConfigVersion
	if err := s.syncCall(ctx, rc, syncapi.OpConfigHistory, syncapi.ConfigHistoryParams{Limit: 30}, &hist); err == nil {
		d["History"] = hist
	}
	d["Groups"] = s.syncGroupNames(ctx, rc, cfg.Settings)
	rc.render(http.StatusOK, "sync_config", d)
}

func (s *Server) handleSyncExport(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var ex syncapi.ConfigExport
	if err := s.syncCall(ctx, rc, syncapi.OpConfigExport, nil, &ex); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync/config")
		return
	}
	s.audit(ctx, rc, "sync.config_export", "google", "", store.ResultOK)
	rc.w.Header().Set("Content-Type", "application/toml; charset=utf-8")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-sync-`+s.now().UTC().Format("20060102-150405")+`.toml"`)
	_, _ = rc.w.Write([]byte(ex.TOML))
}
