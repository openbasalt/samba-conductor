package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/directory"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Import from Google Workspace: the pages. The administrator chooses
// filters (Google side) and where the objects go (AD side); conductor asks
// conductor-sync for the import plan (a read of Google with the read-only
// scopes), shows it, and on request builds a bulk job of kind importKind
// whose preview lists every AD write and every conflict. Applying the job
// needs re-authentication; each row is audited.

// importReadTimeout bounds the read of the Google directory (conductor-sync
// answers within 150 s).
const importReadTimeout = 140 * time.Second

// importShown bounds the users and groups listed on the page (the job
// preview lists them all).
const importShown = 300

// importForm is the form of the import page.
type importForm struct {
	OrgUnits, MemberOf, GroupEmails             string
	SubOrgUnits, Suspended, Admins, Groups      bool
	SkipEmptyGroups, Enabled                    bool
	UserOU, GroupOU, Fallback, MaxUsers, MaxRun string
}

func defaultImportForm(cfg *syncapi.ConfigView) importForm {
	f := importForm{SkipEmptyGroups: true, Enabled: true, Fallback: defaultFallback, MaxUsers: "500", MaxRun: "50"}
	if cfg != nil {
		if b := cfg.Settings.Scope.UserBases; len(b) > 0 {
			f.UserOU = b[0]
		}
		if b := cfg.Settings.Scope.GroupBases; len(b) > 0 {
			f.GroupOU = b[0]
		}
	}
	return f
}

func (rc *reqCtx) importForm() importForm {
	on := func(k string) bool { return rc.form(k) == "1" }
	return importForm{OrgUnits: rc.form("org_units"), MemberOf: rc.form("member_of"), GroupEmails: rc.form("group_emails"),
		SubOrgUnits: on("sub_org_units"), Suspended: on("include_suspended"), Admins: on("include_admins"), Groups: on("groups"),
		SkipEmptyGroups: on("skip_empty_groups"), Enabled: rc.form("enabled") != "0", UserOU: rc.form("user_ou"),
		GroupOU: rc.form("group_ou"), Fallback: strings.ToLower(rc.form("fallback")), MaxUsers: rc.form("max_users"), MaxRun: rc.form("max_run")}
}

// splitLines splits a text area into distinct values (lines, commas or
// semicolons).
func splitLines(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ';' }) {
		if v = strings.TrimSpace(v); v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}

// params validates the form into the import.plan request and the AD
// options; the error is an i18n key.
func (f importForm) params(base string, maxRows int) (syncapi.ImportPlanParams, importOptions, string) {
	p := syncapi.ImportPlanParams{OrgUnits: splitLines(f.OrgUnits), SubOrgUnits: f.SubOrgUnits, MemberOf: lowerAll(splitLines(f.MemberOf)),
		IncludeSuspended: f.Suspended, IncludeAdmins: f.Admins, Groups: f.Groups, SkipEmptyGroups: f.SkipEmptyGroups}
	if f.Groups {
		p.GroupEmails = lowerAll(splitLines(f.GroupEmails))
	}
	opt := importOptions{UserOU: f.UserOU, Enabled: f.Enabled, Fallback: f.Fallback}
	if f.Groups {
		opt.GroupOU = f.GroupOU
	}
	maxUsers, err1 := strconv.Atoi(f.MaxUsers)
	maxRun, err2 := strconv.Atoi(f.MaxRun)
	switch {
	case err1 != nil || maxUsers < 1 || maxUsers > min(maxRows, syncapi.MaxImportUsers):
		return p, opt, "import.err.max_users"
	case err2 != nil || maxRun < 1 || maxRun > maxRows:
		return p, opt, "import.err.max_run"
	case !validParent(opt.UserOU, base) || (f.Groups && !validParent(opt.GroupOU, base)):
		return p, opt, "form.invalid_parent"
	case !validFallback(opt.Fallback):
		return p, opt, "import.err.fallback"
	}
	p.MaxUsers, opt.Max = maxUsers, maxRun
	if f.Groups {
		p.MaxGroups = min(syncapi.MaxImportGroups, max(1, maxRows-maxUsers))
	}
	if err := p.Validate(); err != nil {
		return p, opt, "import.err.filters"
	}
	return p, opt, ""
}

// realmBase is the domain's DN from its realm (LAB.TEST -> DC=lab,DC=test).
func realmBase(realm string) string {
	parts := strings.Split(strings.ToLower(realm), ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

func lowerAll(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(in[i])
	}
	return in
}

// underAny reports whether dn is one of the bases or below one.
func underAny(dn string, bases []string) bool {
	for _, b := range bases {
		if validParent(dn, b) {
			return true
		}
	}
	return false
}

// importWarnings compares the choices with conductor-sync's settings: the
// imported objects are only useful if the sync picks them up and adopts
// the Google accounts by address.
func importWarnings(t func(string, ...any) string, cfg *syncapi.ConfigView, f importForm) []string {
	if cfg == nil {
		return nil
	}
	st := cfg.Settings
	var out []string
	if st.Policy.Adopt != "email" {
		out = append(out, t("import.warn.adopt"))
	}
	if len(st.Mapping.PrimaryEmail) == 0 || !strings.Contains(strings.ToLower(st.Mapping.PrimaryEmail[0]), "{mail") {
		out = append(out, t("import.warn.mail_template"))
	}
	if f.UserOU != "" && !underAny(f.UserOU, st.Scope.UserBases) {
		out = append(out, t("import.warn.user_scope"))
	}
	if len(st.Scope.IncludeGroups) > 0 {
		out = append(out, t("import.warn.include_groups"))
	}
	if f.Groups {
		if len(st.Mapping.GroupEmail) == 0 || !underAny(f.GroupOU, st.Scope.GroupBases) {
			out = append(out, t("import.warn.group_scope"))
		} else if !strings.Contains(strings.ToLower(st.Mapping.GroupEmail[0]), "{mail") {
			out = append(out, t("import.warn.group_mail_template"))
		}
	}
	return out
}

// handleSyncImport shows the import form.
func (s *Server) handleSyncImport(rc *reqCtx) {
	if s.sync == nil {
		rc.render(http.StatusOK, "sync_import", map[string]any{"Disabled": true})
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	d := map[string]any{"MaxRows": s.cfg.Bulk.MaxRows}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		d["Error"] = s.syncErr(rc, err)
	} else {
		d["Cfg"] = &cfg
	}
	cfgp, _ := d["Cfg"].(*syncapi.ConfigView)
	f := defaultImportForm(cfgp)
	s.renderImport(rc, http.StatusOK, d, f, nil)
}

// renderImport renders the page with the OU pickers.
func (s *Server) renderImport(rc *reqCtx, status int, d map[string]any, f importForm, plan *syncapi.ImportPlan) {
	cfg, _ := d["Cfg"].(*syncapi.ConfigView)
	d["F"] = f
	d["Warnings"] = importWarnings(rc.T, cfg, f)
	if plan != nil {
		d["Plan"] = plan
		d["Users"], d["Groups"] = plan.Users, plan.Groups
		if len(plan.Users) > importShown {
			d["Users"], d["MoreUsers"] = plan.Users[:importShown], len(plan.Users)-importShown
		}
		if len(plan.Groups) > importShown {
			d["Groups"], d["MoreGroups"] = plan.Groups[:importShown], len(plan.Groups)-importShown
		}
	}
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	var opts []ouOption
	err := rc.withConn(ctx, func(conn *ad.Conn) error {
		var err error
		opts, err = ouOptions(ctx, conn)
		return err
	})
	if errors.Is(err, directory.ErrCredentialClosed) || errors.Is(err, ad.ErrSessionClosed) {
		rc.failed(err)
		return
	}
	if err != nil {
		// The page still works with the OUs already chosen.
		s.log.Warn("import: directory read failed", "err", err)
		d["DirError"] = rc.T(s.adErrorKey(err))
		for _, dn := range []string{f.UserOU, f.GroupOU} {
			if dn != "" && !slices.ContainsFunc(opts, func(o ouOption) bool { return o.DN == dn }) {
				opts = append(opts, ouOption{DN: dn, Label: dn})
			}
		}
	}
	d["OUs"] = opts
	rc.render(status, "sync_import", d)
}

// handleSyncImportPost reads the import plan (step "read") or builds the
// job from a fresh read (step "build").
func (s *Server) handleSyncImportPost(rc *reqCtx) {
	if s.sync == nil {
		rc.errorPage(http.StatusNotFound, "sync.err.disabled")
		return
	}
	f := rc.importForm()
	d := map[string]any{"MaxRows": s.cfg.Bulk.MaxRows}
	ctx, cancel := context.WithTimeout(rc.ctx(), importReadTimeout)
	defer cancel()
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		d["Error"] = s.syncErr(rc, err)
		s.renderImport(rc, http.StatusOK, d, f, nil)
		return
	}
	d["Cfg"] = &cfg
	// The job builder checks the OUs again against the DC's naming context.
	p, opt, bad := f.params(realmBase(s.backend.Realm()), s.cfg.Bulk.MaxRows)
	if bad != "" {
		d["Error"] = rc.T(bad)
		s.renderImport(rc, http.StatusBadRequest, d, f, nil)
		return
	}
	var plan syncapi.ImportPlan
	if err := s.syncCall(ctx, rc, syncapi.OpImportPlan, p, &plan); err != nil {
		s.audit(ctx, rc, "sync.import.read", "google", s.syncErr(rc, err), store.ResultFailed)
		d["Error"] = s.syncErr(rc, err)
		s.renderImport(rc, http.StatusOK, d, f, nil)
		return
	}
	s.audit(ctx, rc, "sync.import.read", "google", fmt.Sprintf("users=%d groups=%d skipped=%v", len(plan.Users), len(plan.Groups), plan.SkippedCounts),
		store.ResultOK)
	if rc.form("step") != "build" {
		s.renderImport(rc, http.StatusOK, d, f, &plan)
		return
	}
	inputs := importInputs(&plan, opt)
	if len(inputs) == 0 {
		d["Error"] = rc.T("import.err.empty")
		s.renderImport(rc, http.StatusOK, d, f, &plan)
		return
	}
	s.createJob(rc, importKind, rc.T("bulk.kind."+importKind), inputs, func(errs []rowError) {
		rc.render(http.StatusBadRequest, "bulk_errors", map[string]any{"Errors": errs, "Back": "/admin/sync/import"})
	})
}

// importInputs turns an import plan into job inputs: users first, then
// groups (their members by address).
func importInputs(plan *syncapi.ImportPlan, opt importOptions) []map[string]string {
	var out []map[string]string
	for _, u := range plan.Users {
		in := map[string]string{"type": importUser, "email": u.Email, "given": u.GivenName, "family": u.FamilyName, "title": u.Title,
			"department": u.Department, "employee_id": u.EmployeeID, "phone_work": u.PhoneWork, "phone_mobile": u.PhoneMobile,
			"google_org_unit": u.OrgUnit}
		if u.Suspended {
			in["suspended"] = "1"
		}
		opt.put(in)
		out = append(out, in)
	}
	for _, g := range plan.Groups {
		in := map[string]string{"type": importGroup, "email": g.Email, "name": g.Name, "description": g.Description,
			"users": strings.Join(g.Users, ";"), "groups": strings.Join(g.Groups, ";")}
		opt.put(in)
		out = append(out, in)
	}
	return out
}
