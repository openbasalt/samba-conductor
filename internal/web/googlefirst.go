package web

import (
	"context"
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

// Google-first mode (Google Workspace to AD), phase B1: users only, manual
// apply only. conductor-sync reads Google and AD (read-only) and returns a
// plan (g2a.plan); conductor shows it, applies the operations an
// administrator approves through conductor-provisioner, then reports what
// it applied (g2a.confirm). The settings are the [google_first] section of
// conductor-sync's settings, saved through config.update like every other
// sync setting.
//
// Security premises: nothing from Google grants anything privileged in AD
// and privileged accounts are never touched (P1, enforced by the plan and
// again by the provisioner); Google owns its fields, which conductor shows
// read only (P2); conductor-idp never serves Google while the mode is on
// (P3, googlefirst_p3.go). Every change is previewed and confirmed with
// the password and a fresh second factor; switching a scope to apply also
// needs the latest plan reviewed and a typed confirmation.

// gfOn reports whether the section can work: [sync] and [provisioner].
func (s *Server) gfOn() bool { return s.sync != nil && s.prov != nil }

// gfMissing lists what the section needs but lacks ("sync",
// "provisioner").
func (s *Server) gfMissing() []string {
	var out []string
	if s.sync == nil {
		out = append(out, "sync")
	}
	if s.prov == nil {
		out = append(out, "provisioner")
	}
	return out
}

// gfCache keeps the Google-first settings for the "Managed by Google"
// checks of the user pages (one API call per 30 s at most).
type gfCache struct {
	mu sync.Mutex
	gf *syncapi.GoogleFirstSettings
	at time.Time
}

// gfCacheTTL bounds how long the cached settings are used.
const gfCacheTTL = 30 * time.Second

// googleFirst returns the Google-first settings (zero when the section is
// absent), from the cache unless fresh is set.
func (s *Server) googleFirst(ctx context.Context, rc *reqCtx, fresh bool) (syncapi.GoogleFirstSettings, error) {
	if s.sync == nil {
		return syncapi.GoogleFirstSettings{}, errSyncDisabled
	}
	if !fresh {
		s.gfCache.mu.Lock()
		gf, at := s.gfCache.gf, s.gfCache.at
		s.gfCache.mu.Unlock()
		if gf != nil && s.now().Sub(at) < gfCacheTTL {
			return *gf, nil
		}
	}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		return syncapi.GoogleFirstSettings{}, err
	}
	gf := googleFirstOf(cfg.Settings)
	s.gfCache.mu.Lock()
	s.gfCache.gf, s.gfCache.at = &gf, s.now()
	s.gfCache.mu.Unlock()
	return gf, nil
}

// gfForget drops the cached settings (after a save).
func (s *Server) gfForget() {
	s.gfCache.mu.Lock()
	s.gfCache.gf = nil
	s.gfCache.mu.Unlock()
}

// gfDisabled renders the page of a section that cannot work.
func (s *Server) gfDisabled(rc *reqCtx) bool {
	if s.gfOn() {
		return false
	}
	rc.render(http.StatusOK, "google_first", map[string]any{"Missing": s.gfMissing()})
	return true
}

// gfScopeRow is one scope on the overview.
type gfScopeRow struct {
	syncapi.G2AScope
	// Last is the scope's part of the latest plan (nil when the latest
	// plan does not cover it).
	Last *syncapi.G2AScopePlan
}

// handleGoogleFirst is the overview: status, the enablement form, the
// scopes, the latest plan and the P3 check.
func (s *Server) handleGoogleFirst(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSyncWrite)}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		d["Error"] = s.syncErr(rc, err)
		rc.render(http.StatusOK, "google_first", d)
		return
	}
	gf := googleFirstOf(cfg.Settings)
	d["GF"], d["Version"] = gf, cfg.Version
	last, runs, err := s.g2aLatest(ctx, rc)
	if err != nil {
		d["RunsError"] = s.syncErr(rc, err)
	}
	d["Runs"] = runs
	rows := make([]gfScopeRow, 0, len(gf.Scopes))
	for _, sc := range gf.Scopes {
		row := gfScopeRow{G2AScope: sc}
		if last != nil && last.G2A != nil {
			for i := range last.G2A.Scopes {
				if last.G2A.Scopes[i].Name == sc.Name {
					row.Last = &last.G2A.Scopes[i]
				}
			}
		}
		rows = append(rows, row)
	}
	d["Scopes"] = rows
	if last != nil {
		d["Last"] = last
	}
	if gf.Enabled || gf.GoogleDomain != "" {
		d["P3"] = s.p3Check(ctx, rc, gf.GoogleDomain)
	}
	rc.render(http.StatusOK, "google_first", d)
}

// g2aLatest returns the latest g2a run with the first page of its plan,
// and the recent g2a runs (newest first).
func (s *Server) g2aLatest(ctx context.Context, rc *reqCtx) (*syncapi.RunDetail, []syncapi.Run, error) {
	var list syncapi.RunsList
	if err := s.syncCall(ctx, rc, syncapi.OpRunsList, syncapi.RunsListParams{Limit: 100}, &list); err != nil {
		return nil, nil, err
	}
	var runs []syncapi.Run
	for _, r := range list.Runs {
		if r.Action == syncapi.RunActionG2A {
			runs = append(runs, r)
		}
	}
	if len(runs) == 0 {
		return nil, nil, nil
	}
	var det syncapi.RunDetail
	if err := s.syncCall(ctx, rc, syncapi.OpRunGet, syncapi.RunGetParams{ID: runs[0].ID, Limit: 1}, &det); err != nil {
		return nil, runs, err
	}
	if len(runs) > 8 {
		runs = runs[:8]
	}
	return &det, runs, nil
}

// ---- saving the section ----

// gfSave describes one change of the section to propose.
type gfSave struct {
	action, target       string
	title, summary, warn string
	reauthKey            string
	back, done           string
	// note is a translated line added to the preview.
	note string
}

// gfPropose validates next with conductor-sync (the whole settings with
// the new section) and proposes saving it as a new version. When the mode
// is (or stays) on, P3 is checked now and again at confirmation.
func (s *Server) gfPropose(ctx context.Context, rc *reqCtx, cfg syncapi.ConfigView, next syncapi.GoogleFirstSettings, sv gfSave, errBack func(string)) {
	settings := cfg.Settings
	gfNext := next
	settings.GoogleFirst = &gfNext
	if next.Enabled {
		if r := s.p3Check(ctx, rc, next.GoogleDomain); !r.OK() {
			s.audit(ctx, rc, "g2a.p3_refused", sv.target, r.summary(), store.ResultDenied)
			errBack(s.errMessage(rc.T, p3Error(r)))
			return
		}
	}
	var v syncapi.ConfigValidateResult
	if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: settings}, &v); err != nil {
		errBack(s.syncErr(rc, err))
		return
	}
	if !v.Valid {
		errBack(rc.T("gf.err.invalid") + " " + strings.Join(v.Errors, "; "))
		return
	}
	if len(v.Changes) == 0 {
		rc.flashOK("form.no_change")
		rc.redirect(sv.back)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conductor-sync %s\nbase_version: %d\n", syncapi.OpConfigUpdate, cfg.Version)
	for _, c := range v.Changes {
		fmt.Fprintf(&b, "%s\n", c.String())
	}
	if sv.note != "" {
		fmt.Fprintf(&b, "# %s\n", sv.note)
	}
	if next.Enabled {
		b.WriteString("# P3: checked again at confirmation\n")
	}
	base := cfg.Version
	rc.propose(&pendingOp{perm: PermSyncWrite, action: sv.action, target: sv.target, reauth: true, reauthKey: sv.reauthKey,
		title: sv.title, summary: sv.summary, warning: sv.warn, preview: strings.TrimRight(b.String(), "\n"),
		run: func(ctx context.Context, rc *reqCtx) error {
			if next.Enabled {
				if r := s.p3Check(ctx, rc, next.GoogleDomain); !r.OK() {
					s.audit(ctx, rc, "g2a.p3_refused", sv.target, r.summary(), store.ResultDenied)
					return p3Error(r)
				}
			}
			defer s.gfForget()
			return s.syncCall(ctx, rc, syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: base, Settings: settings,
				Comment: sv.action + " (conductor)"}, &syncapi.ConfigUpdateResult{})
		},
		back: sv.back, done: sv.done})
}

// gfConfig reads the configuration for a change; on failure it flashes the
// error and redirects to the overview.
func (s *Server) gfConfig(ctx context.Context, rc *reqCtx) (syncapi.ConfigView, bool) {
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/google-first")
		return cfg, false
	}
	return cfg, true
}

// handleGoogleFirstSettings previews switching the mode on or off and
// changing the Google domain.
func (s *Server) handleGoogleFirstSettings(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	cfg, ok := s.gfConfig(ctx, rc)
	if !ok {
		return
	}
	before := googleFirstOf(cfg.Settings)
	next := before
	next.Enabled = rc.form("enabled") == "1"
	next.GoogleDomain = strings.ToLower(rc.form("google_domain"))
	errBack := func(msg string) {
		rc.sess.addFlash("error", msg)
		rc.redirect("/admin/google-first")
	}
	if next.Enabled && next.GoogleDomain == "" {
		errBack(rc.T("gf.err.domain_required"))
		return
	}
	sv := gfSave{action: "google_first.settings", target: "google-first", title: rc.T("gf.settings.title"),
		summary: rc.T("gf.settings.summary"), back: "/admin/google-first", done: rc.T("gf.settings.saved")}
	switch {
	case next.Enabled && !before.Enabled:
		sv.action, sv.title, sv.summary = "google_first.enable", rc.T("gf.enable.title"), rc.T("gf.enable.summary", next.GoogleDomain)
		sv.warn = rc.T("gf.enable.warning")
		sv.note = rc.T("gf.enable.note")
	case !next.Enabled && before.Enabled:
		sv.action, sv.title, sv.summary = "google_first.disable", rc.T("gf.disable.title"), rc.T("gf.disable.summary")
	}
	s.gfPropose(ctx, rc, cfg, next, sv, errBack)
}

// ---- scopes ----

// gfFieldAttrs maps the optional scope fields to the AD attributes Google
// owns when the field is listed.
var gfFieldAttrs = []struct{ Field, Attr string }{
	{"title", "title"}, {"department", "department"}, {"employee_id", "employeeID"},
	{"phone_work", "telephoneNumber"}, {"phone_mobile", "mobile"},
}

// gfDefaultLimits are the limits of a new scope (conductor-sync's
// defaults).
func gfDefaultLimits() syncapi.G2ALimits {
	return syncapi.G2ALimits{MaxCreates: 20, MaxDisables: 5, MaxReenables: 20, MaxUpdates: 50, MaxRenames: 5,
		MaxTouchedPercent: 20, MinSourceSize: 1, MaxSourceDropPercent: 20}
}

// gfScopeForm is the scope form as posted.
type gfScopeForm struct {
	Edit bool
	syncapi.G2AScope
	OrgUnitsText, MemberOfText string
	L                          syncapi.G2ALimits
}

func scopeFormFrom(sc syncapi.G2AScope, edit bool) gfScopeForm {
	f := gfScopeForm{Edit: edit, G2AScope: sc, OrgUnitsText: strings.Join(sc.OrgUnits, "\n"), MemberOfText: strings.Join(sc.MemberOf, "\n"),
		L: gfDefaultLimits()}
	if sc.Limits != nil {
		f.L = *sc.Limits
	}
	return f
}

// scopeFromForm reads the scope form; ok is false when a number does not
// parse.
func scopeFromForm(rc *reqCtx) (gfScopeForm, bool) {
	_ = rc.r.ParseForm()
	f := gfScopeForm{Edit: rc.form("edit") == "1", OrgUnitsText: rc.form("org_units"), MemberOfText: rc.form("member_of")}
	f.Name = strings.ToLower(rc.form("name"))
	f.ManagedOU, f.GroupsOU, f.QuarantineOU = rc.form("managed_ou"), rc.form("groups_ou"), rc.form("quarantine_ou")
	f.OrgUnits, f.MemberOf = formLines(f.OrgUnitsText), formLines(f.MemberOfText)
	f.SubOrgUnits = rc.form("sub_org_units") == "1"
	f.LogonTemplate = rc.form("logon_template")
	for _, fa := range gfFieldAttrs {
		if slices.Contains(rc.r.PostForm["fields"], fa.Field) {
			f.Fields = append(f.Fields, fa.Field)
		}
	}
	ok := true
	num := func(k string, dst *int) {
		v, err := strconv.Atoi(rc.form(k))
		if err != nil {
			ok = false
		}
		*dst = v
	}
	pct := func(k string, dst *float64) {
		v, err := strconv.ParseFloat(rc.form(k), 64)
		if err != nil {
			ok = false
		}
		*dst = v
	}
	num("max_creates", &f.L.MaxCreates)
	num("max_disables", &f.L.MaxDisables)
	num("max_reenables", &f.L.MaxReenables)
	num("max_updates", &f.L.MaxUpdates)
	num("max_renames", &f.L.MaxRenames)
	pct("max_touched_percent", &f.L.MaxTouchedPercent)
	num("min_source_size", &f.L.MinSourceSize)
	pct("max_source_drop_percent", &f.L.MaxSourceDropPercent)
	l := f.L
	f.Limits = &l
	return f, ok
}

// gfScopeIndex returns the index of a scope by name (-1 when absent).
func gfScopeIndex(gf syncapi.GoogleFirstSettings, name string) int {
	return slices.IndexFunc(gf.Scopes, func(sc syncapi.G2AScope) bool { return sc.Name == name })
}

func (s *Server) renderScopeForm(rc *reqCtx, status int, f gfScopeForm, errMsg string) {
	rc.render(status, "google_first_scope", map[string]any{"F": f, "Fields": gfFieldAttrs, "Error": errMsg})
}

// handleGoogleFirstScopeNew shows an empty scope form.
func (s *Server) handleGoogleFirstScopeNew(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	s.renderScopeForm(rc, http.StatusOK, scopeFormFrom(syncapi.G2AScope{Mode: syncapi.G2AModeDryRun, SubOrgUnits: true,
		Fields: []string{"title", "department"}}, false), "")
}

// handleGoogleFirstScope shows the form of an existing scope.
func (s *Server) handleGoogleFirstScope(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	cfg, ok := s.gfConfig(ctx, rc)
	if !ok {
		return
	}
	gf := googleFirstOf(cfg.Settings)
	i := gfScopeIndex(gf, rc.r.PathValue("name"))
	if i < 0 {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	s.renderScopeForm(rc, http.StatusOK, scopeFormFrom(gf.Scopes[i], true), "")
}

// scopeSelectionChanged reports whether an edit changes what a scope
// selects or where it writes (anything but the limits).
func scopeSelectionChanged(a, b syncapi.G2AScope) bool {
	return a.ManagedOU != b.ManagedOU || a.GroupsOU != b.GroupsOU || a.QuarantineOU != b.QuarantineOU ||
		!slices.Equal(a.OrgUnits, b.OrgUnits) || a.SubOrgUnits != b.SubOrgUnits || !slices.Equal(a.MemberOf, b.MemberOf) ||
		!slices.Equal(a.Fields, b.Fields) || a.LogonTemplate != b.LogonTemplate
}

// handleGoogleFirstScopePost previews adding or changing a scope. A new
// scope starts in dry-run; an edit that changes what an apply scope
// selects puts it back in dry-run (its next plan is a preview again).
func (s *Server) handleGoogleFirstScopePost(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	f, ok := scopeFromForm(rc)
	if !ok {
		s.renderScopeForm(rc, http.StatusBadRequest, f, rc.T("gf.scope.err_numbers"))
		return
	}
	if !syncapi.ValidG2AScopeName(f.Name) {
		s.renderScopeForm(rc, http.StatusBadRequest, f, rc.T("gf.scope.err_name"))
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	cfg, okc := s.gfConfig(ctx, rc)
	if !okc {
		return
	}
	next := googleFirstOf(cfg.Settings)
	i := gfScopeIndex(next, f.Name)
	sc := f.G2AScope
	sv := gfSave{target: "scope " + f.Name, back: "/admin/google-first", done: rc.T("gf.scope.saved", f.Name)}
	switch {
	case f.Edit && i < 0:
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	case f.Edit:
		old := next.Scopes[i]
		sc.Mode = old.Mode
		if old.Mode == syncapi.G2AModeApply && scopeSelectionChanged(old, sc) {
			sc.Mode = syncapi.G2AModeDryRun
			sv.note = rc.T("gf.scope.back_to_dry_run")
			sv.warn = rc.T("gf.scope.back_to_dry_run")
		}
		next.Scopes[i] = sc
		sv.action, sv.title, sv.summary = "google_first.scope_update", rc.T("gf.scope.update_title", f.Name), rc.T("gf.scope.update_summary", f.Name)
	case i >= 0:
		s.renderScopeForm(rc, http.StatusBadRequest, f, rc.T("gf.scope.err_exists", f.Name))
		return
	default:
		sc.Mode = syncapi.G2AModeDryRun
		next.Scopes = append(next.Scopes, sc)
		sv.action, sv.title, sv.summary = "google_first.scope_add", rc.T("gf.scope.add_title", f.Name), rc.T("gf.scope.add_summary", f.Name)
	}
	s.gfPropose(ctx, rc, cfg, next, sv, func(msg string) { s.renderScopeForm(rc, http.StatusBadRequest, f, msg) })
}

// handleGoogleFirstScopeRemove previews removing a scope (typed name).
// The accounts stay in AD as they are; their fields become AD-managed.
func (s *Server) handleGoogleFirstScopeRemove(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	name := rc.r.PathValue("name")
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	cfg, ok := s.gfConfig(ctx, rc)
	if !ok {
		return
	}
	next := googleFirstOf(cfg.Settings)
	i := gfScopeIndex(next, name)
	if i < 0 {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	if rc.form("confirm") != name {
		s.audit(ctx, rc, "google_first.scope_remove", "scope "+name, "typed confirmation did not match", store.ResultDenied)
		rc.flashErr("gf.confirm_mismatch", name)
		rc.redirect("/admin/google-first")
		return
	}
	next.Scopes = slices.Delete(next.Scopes, i, i+1)
	s.gfPropose(ctx, rc, cfg, next, gfSave{action: "google_first.scope_remove", target: "scope " + name,
		title: rc.T("gf.scope.remove_title", name), summary: rc.T("gf.scope.remove_summary", name), warn: rc.T("gf.scope.remove_warning"),
		back: "/admin/google-first", done: rc.T("gf.scope.removed", name)},
		func(msg string) {
			rc.sess.addFlash("error", msg)
			rc.redirect("/admin/google-first")
		})
}

// ---- scope mode ----

// modeConfirmation is the text typed to switch a scope to apply: its name
// and the first 8 characters of the reviewed plan's digest.
func modeConfirmation(scope, digest string) string {
	if len(digest) > 8 {
		digest = digest[:8]
	}
	return scope + " " + digest
}

// handleGoogleFirstScopeMode switches a scope between dry-run and apply.
// To apply: the run posted must be the latest g2a plan and cover the
// scope (the plan the administrator reviewed), the scope name plus the
// first 8 characters of its digest must be typed, and the confirmation
// asks for the password and a fresh second factor. Back to dry-run needs
// the confirmation only.
func (s *Server) handleGoogleFirstScopeMode(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	name, mode := rc.r.PathValue("name"), rc.form("mode")
	if mode != syncapi.G2AModeApply && mode != syncapi.G2AModeDryRun {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	cfg, ok := s.gfConfig(ctx, rc)
	if !ok {
		return
	}
	next := googleFirstOf(cfg.Settings)
	i := gfScopeIndex(next, name)
	if i < 0 {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	back := "/admin/google-first"
	if next.Scopes[i].Mode == mode {
		rc.flashOK("form.no_change")
		rc.redirect(back)
		return
	}
	sv := gfSave{action: "google_first.mode", target: "scope " + name, back: back, done: rc.T("gf.mode.done", name, mode)}
	if mode == syncapi.G2AModeApply {
		runID, err := strconv.ParseInt(rc.form("run"), 10, 64)
		if err != nil || runID <= 0 {
			rc.errorPage(http.StatusBadRequest, "form.invalid")
			return
		}
		back = fmt.Sprintf("/admin/google-first/runs/%d", runID)
		sv.back = back
		if key := s.modeGate(ctx, rc, name, runID); key != "" {
			s.audit(ctx, rc, "google_first.mode", "scope "+name, key, store.ResultDenied)
			rc.flashErr(key, name)
			rc.redirect(back)
			return
		}
		if !next.Enabled {
			rc.flashErr("gf.mode.err_off")
			rc.redirect(back)
			return
		}
		sv.title, sv.summary = rc.T("gf.mode.apply_title", name), rc.T("gf.mode.apply_summary", name)
		sv.warn, sv.reauthKey = rc.T("gf.mode.apply_warning"), "gf.mode.reauth"
		sv.note = fmt.Sprintf("reviewed plan: run %d", runID)
	} else {
		sv.title, sv.summary = rc.T("gf.mode.dry_run_title", name), rc.T("gf.mode.dry_run_summary", name)
	}
	next.Scopes[i].Mode = mode
	s.gfPropose(ctx, rc, cfg, next, sv, func(msg string) {
		rc.sess.addFlash("error", msg)
		rc.redirect(back)
	})
}

// modeGate checks the typed confirmation of a switch to apply against a
// fresh read of the latest plan ("" when it holds, else a message key).
func (s *Server) modeGate(ctx context.Context, rc *reqCtx, scope string, runID int64) string {
	last, _, err := s.g2aLatest(ctx, rc)
	if err != nil || last == nil {
		return "gf.mode.err_no_plan"
	}
	if last.Run.ID != runID || last.G2A == nil {
		return "gf.mode.err_not_latest"
	}
	covered := slices.ContainsFunc(last.G2A.Scopes, func(sp syncapi.G2AScopePlan) bool { return sp.Name == scope })
	if !covered {
		return "gf.mode.err_not_covered"
	}
	if rc.form("confirm") != modeConfirmation(scope, last.G2A.Digest) {
		return "gf.mode.err_confirm"
	}
	return ""
}
