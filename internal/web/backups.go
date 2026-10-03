package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor/internal/store"
)

// Backups (P3). conductor never touches backups itself: conductor-backup
// (its own user) does the work, conductor-helper (root) takes the online
// backup and keeps the request and policy files; conductor reads the status
// and asks for actions through the helper, with the signed-in user as the
// caller.

// systemCaller is how conductor identifies itself to the helper for its
// own background reads (not attributed to a user).
var systemCaller = helper.Caller{User: "conductor", SID: "S-1-5-18", SessionID: "background-poller"}

// schedulerGrace: conductor-backup.timer runs hourly; no run for this long
// means the scheduler is not working.
const schedulerGrace = 2*time.Hour + 15*time.Minute

// backupCache is the last status the poller read (dashboard banner).
type backupCache struct {
	mu sync.Mutex
	st helper.BackupStatus
	at time.Time
	ok bool
}

func (c *backupCache) set(st helper.BackupStatus, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st, c.at, c.ok = st, at, true
}

func (c *backupCache) get() (helper.BackupStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st, c.ok
}

// helperCallWith runs one helper operation with parameters as the
// signed-in user and audits it (helper.call).
func (s *Server) helperCallWith(ctx context.Context, rc *reqCtx, op helper.OpName, params helper.Params, out any) error {
	if s.helper == nil {
		return errHelperDisabled
	}
	rc.sess.mu.Lock()
	caller := helper.Caller{User: rc.sess.sam, SID: rc.sess.userSID.String(), SessionID: rc.sess.hash[:16], SourceIP: rc.ip}
	rc.sess.mu.Unlock()
	req, err := helper.NewRequest(newToken()[:24], op, caller, params)
	if err != nil {
		return err
	}
	resp, err := s.helper.Call(ctx, req)
	d := map[string]any{"op": op, "id": req.ID}
	if params != nil {
		d["params"] = params
	}
	detail, _ := json.Marshal(d)
	if err != nil {
		s.audit(ctx, rc, "helper.call", string(op), string(detail), store.ResultFailed)
		return err
	}
	s.audit(ctx, rc, "helper.call", string(op), string(detail), store.ResultOK)
	if out == nil {
		return nil
	}
	return helper.DecodeResult(resp, out)
}

// systemBackupStatus reads the status as conductor itself (poller).
func (s *Server) systemBackupStatus(ctx context.Context) (helper.BackupStatus, error) {
	var st helper.BackupStatus
	if s.helper == nil {
		return st, errHelperDisabled
	}
	req, err := helper.NewRequest(newToken()[:24], helper.OpBackupStatus, systemCaller, nil)
	if err != nil {
		return st, err
	}
	resp, err := s.helper.Call(ctx, req)
	if err != nil {
		return st, err
	}
	return st, helper.DecodeResult(resp, &st)
}

// pollBackups refreshes the cache and records new results. Errors are
// logged once per change, not on every tick.
func (s *Server) pollBackups(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := s.systemBackupStatus(ctx)
	if err != nil {
		if s.backupPollErr == "" || s.backupPollErr != err.Error() {
			s.log.Warn("backup status unavailable", "err", err)
		}
		s.backupPollErr = err.Error()
		return
	}
	s.backupPollErr = ""
	s.backups.set(st, s.now())
	s.ingestBackupResults(ctx, st)
}

// ingestBackupResults records every backup run and drill the first time
// conductor sees it, in its own state and in the audit log.
func (s *Server) ingestBackupResults(ctx context.Context, st helper.BackupStatus) {
	backups := append([]helper.BackupRecord(nil), st.Backups...)
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.Before(backups[j].CreatedAt) })
	for _, b := range backups {
		if b.Status == helper.StatusPruned {
			continue
		}
		var dests []string
		for _, u := range b.Uploads {
			dests = append(dests, u.Destination+":"+u.Status)
		}
		detail, _ := json.Marshal(map[string]any{"trigger": b.Trigger, "requested_by": b.RequestedBy, "status": b.Status, "size": b.Size,
			"sha256": b.SHA256, "users": b.Users, "destinations": dests, "error": b.Error, "duration_ms": b.DurationMS})
		isNew, err := s.store.RecordBackupResult(ctx, store.BackupResult{Kind: "backup", ID: b.ID, At: b.CreatedAt, Result: b.Status, Detail: string(detail)})
		if err != nil || !isNew {
			continue
		}
		result := store.ResultOK
		if b.Status == helper.StatusFailed {
			result = store.ResultFailed
		}
		s.systemAudit(ctx, "conductor-backup", "backup.result", b.ID, string(detail), result)
	}
	drills := append([]helper.DrillRecord(nil), st.Drills...)
	sort.Slice(drills, func(i, j int) bool { return drills[i].StartedAt.Before(drills[j].StartedAt) })
	for _, d := range drills {
		res := "passed"
		if !d.Passed {
			res = "failed"
		}
		var failed []string
		for _, c := range d.Checks {
			if !c.OK {
				failed = append(failed, c.Name)
			}
		}
		detail, _ := json.Marshal(map[string]any{"backup_id": d.BackupID, "host": d.Host, "passed": d.Passed, "rto_ms": d.RTOMS,
			"checks": len(d.Checks), "failed_checks": failed, "error": d.Error, "request_id": d.RequestID})
		isNew, err := s.store.RecordBackupResult(ctx, store.BackupResult{Kind: "drill", ID: d.ID, At: d.StartedAt, Result: res, Detail: string(detail)})
		if err != nil || !isNew {
			continue
		}
		result := store.ResultOK
		if !d.Passed {
			result = store.ResultFailed
		}
		s.systemAudit(ctx, "drill:"+d.Host, "backup.drill_result", d.ID, string(detail), result)
	}
}

// systemAudit appends an event that no signed-in user caused.
func (s *Server) systemAudit(ctx context.Context, actor, action, target, detail, result string) {
	if _, err := s.store.AppendAudit(ctx, store.AuditEvent{ActorName: actor, Action: action, Target: target, Detail: detail, Result: result}); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}

// backupAlert is an alert as shown.
type backupAlert struct {
	Kind  string
	Text  string
	Since time.Time
}

// backupAlerts translates the status's alerts and adds the scheduler
// check (conductor-backup itself cannot report that it does not run).
func (s *Server) backupAlerts(rc *reqCtx, st helper.BackupStatus) []backupAlert {
	if !st.Configured {
		return nil
	}
	var out []backupAlert
	now := s.now()
	for _, a := range st.Alerts {
		out = append(out, backupAlert{Kind: a.Kind, Since: a.Since, Text: rc.T("backups.alert."+a.Kind, a.Detail)})
	}
	switch {
	case st.LastRunAt.IsZero():
		out = append(out, backupAlert{Kind: helper.AlertScheduler, Text: rc.T("backups.alert.never_ran")})
	case now.Sub(st.LastRunAt) > schedulerGrace:
		out = append(out, backupAlert{Kind: helper.AlertScheduler, Since: st.LastRunAt, Text: rc.T("backups.alert.scheduler", shortDur(now.Sub(st.LastRunAt)))})
	}
	// A status read from conductor-backup's last run can lag the policy:
	// recompute staleness against the current time.
	if last, ok := st.LastGood(); ok && !hasAlert(out, helper.AlertStale) &&
		now.Sub(last.CreatedAt) > time.Duration(st.Policy.MaxAgeHours)*time.Hour && st.Policy.MaxAgeHours > 0 {
		out = append(out, backupAlert{Kind: helper.AlertStale, Since: last.CreatedAt,
			Text: rc.T("backups.alert.stale", fmt.Sprintf("%s (%s)", last.ID, shortDur(now.Sub(last.CreatedAt))))})
	}
	return out
}

func hasAlert(list []backupAlert, kind string) bool {
	for _, a := range list {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// shortDur renders a duration compactly ("3 d 4 h", "2 h 5 min", "40 s").
func shortDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d d %d h", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%d min %d s", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
}

// humanBytes renders a size ("8.6 MB").
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

func (s *Server) handleBackups(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermBackupWrite)}
	var st helper.BackupStatus
	if err := s.helperCallWith(ctx, rc, helper.OpBackupStatus, nil, &st); err != nil {
		s.log.Warn("backup status unavailable", "err", err)
		d["Error"] = rc.T("backups.err.helper")
		rc.render(http.StatusOK, "backups", d)
		return
	}
	s.backups.set(st, s.now())
	s.ingestBackupResults(ctx, st)
	d["S"] = st
	d["Alerts"] = s.backupAlerts(rc, st)
	if last, ok := st.LastGood(); ok {
		d["LastGood"] = last
		d["RPO"] = shortDur(s.now().Sub(last.CreatedAt))
	}
	if dr, ok := st.LastPassedDrill(); ok {
		d["LastRTO"] = shortDur(time.Duration(dr.RTOMS) * time.Millisecond)
		d["LastPassed"] = dr
	}
	if len(st.Drills) > 0 {
		d["LastDrill"] = st.Drills[0]
	}
	rc.render(http.StatusOK, "backups", d)
}

// ---- actions ----

func (s *Server) proposeTrigger(rc *reqCtx, action string) {
	key := map[string]string{helper.TriggerBackup: "run", helper.TriggerDrill: "drill"}[action]
	preview := fmt.Sprintf("conductor-helper %s\naction: %s\n# %s", helper.OpBackupTrigger, action, rc.T("backups."+key+".preview"))
	rc.propose(&pendingOp{perm: PermBackupWrite, action: "backup.request_" + action, target: strings.ToUpper(s.cfg.Domain.Realm), reauth: true,
		title: rc.T("backups." + key + ".title"), summary: rc.T("backups." + key + ".summary"), preview: preview,
		run: func(ctx context.Context, rc *reqCtx) error {
			var res helper.BackupTriggerResult
			return s.helperCallWith(ctx, rc, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: action}, &res)
		},
		back: "/admin/backups", done: rc.T("backups." + key + ".done")})
}

func (s *Server) handleBackupRun(rc *reqCtx)   { s.proposeTrigger(rc, helper.TriggerBackup) }
func (s *Server) handleBackupDrill(rc *reqCtx) { s.proposeTrigger(rc, helper.TriggerDrill) }

// ---- policy ----

// backupForm is the policy as the form carries it.
type backupForm struct {
	Time, Every, Daily, Weekly, Monthly, MaxAge, Drill string
}

func formFromBackupPolicy(p helper.BackupPolicy) backupForm {
	i := strconv.Itoa
	return backupForm{Time: p.Schedule.Time, Every: i(p.Schedule.EveryHours), Daily: i(p.Retention.Daily), Weekly: i(p.Retention.Weekly),
		Monthly: i(p.Retention.Monthly), MaxAge: i(p.MaxAgeHours), Drill: i(p.DrillIntervalDays)}
}

func (f backupForm) policy() (helper.BackupPolicy, error) {
	var p helper.BackupPolicy
	var bad bool
	num := func(s string) int {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			bad = true
		}
		return n
	}
	p.Schedule.Time = strings.TrimSpace(f.Time)
	p.Schedule.EveryHours = num(f.Every)
	p.Retention = helper.BackupRetention{Daily: num(f.Daily), Weekly: num(f.Weekly), Monthly: num(f.Monthly)}
	p.MaxAgeHours, p.DrillIntervalDays = num(f.MaxAge), num(f.Drill)
	if bad {
		return p, errBadNumber
	}
	return p, p.Validate()
}

// policyDiff lists the changed fields ("name: old -> new").
func policyDiff(old, nw helper.BackupPolicy) []string {
	var out []string
	add := func(name string, a, b any) {
		if fmt.Sprint(a) != fmt.Sprint(b) {
			out = append(out, fmt.Sprintf("%s: %v -> %v", name, a, b))
		}
	}
	add("schedule.time (UTC)", old.Schedule.Time, nw.Schedule.Time)
	add("schedule.every_hours", old.Schedule.EveryHours, nw.Schedule.EveryHours)
	add("retention.daily", old.Retention.Daily, nw.Retention.Daily)
	add("retention.weekly", old.Retention.Weekly, nw.Retention.Weekly)
	add("retention.monthly", old.Retention.Monthly, nw.Retention.Monthly)
	add("max_age_hours", old.MaxAgeHours, nw.MaxAgeHours)
	add("drill_interval_days", old.DrillIntervalDays, nw.DrillIntervalDays)
	return out
}

func (s *Server) currentBackupPolicy(ctx context.Context, rc *reqCtx) (helper.BackupStatus, error) {
	var st helper.BackupStatus
	err := s.helperCallWith(ctx, rc, helper.OpBackupStatus, nil, &st)
	return st, err
}

func (s *Server) handleBackupConfigPage(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	st, err := s.currentBackupPolicy(ctx, rc)
	if err != nil || !st.Configured {
		rc.errorPage(http.StatusServiceUnavailable, "backups.err.helper")
		return
	}
	rc.render(http.StatusOK, "backups_config", map[string]any{"F": formFromBackupPolicy(st.Policy), "Every": helper.ValidEveryHours})
}

func (s *Server) handleBackupConfig(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	st, err := s.currentBackupPolicy(ctx, rc)
	if err != nil || !st.Configured {
		rc.errorPage(http.StatusServiceUnavailable, "backups.err.helper")
		return
	}
	f := backupForm{Time: rc.form("time"), Every: rc.form("every"), Daily: rc.form("daily"), Weekly: rc.form("weekly"),
		Monthly: rc.form("monthly"), MaxAge: rc.form("max_age"), Drill: rc.form("drill")}
	p, err := f.policy()
	if err != nil {
		rc.render(http.StatusBadRequest, "backups_config", map[string]any{"F": f, "Every": helper.ValidEveryHours, "Error": rc.T("backups.config.err")})
		return
	}
	diff := policyDiff(st.Policy, p)
	if len(diff) == 0 {
		rc.flashOK("form.no_change")
		rc.redirect("/admin/backups")
		return
	}
	preview := fmt.Sprintf("conductor-helper %s\n# %s\n%s", helper.OpBackupPolicySet, rc.T("backups.config.preview"), strings.Join(diff, "\n"))
	rc.propose(&pendingOp{perm: PermBackupWrite, action: "backup.policy_update", target: strings.ToUpper(s.cfg.Domain.Realm), reauth: true,
		title: rc.T("backups.config.title"), summary: rc.T("backups.config.summary"), preview: preview,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.helperCallWith(ctx, rc, helper.OpBackupPolicySet, p, &struct{}{})
		},
		back: "/admin/backups", done: rc.T("backups.config.done")})
}
