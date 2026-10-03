package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// The setup wizard edits a draft of the sync settings held in the
// signed-in session (nothing is stored until the review step is confirmed
// with a fresh second factor). Groups and OUs are picked from the
// directory with the administrator's own AD connection; groups are stored
// by SID, which survives renames and moves.

// syncSteps are the wizard steps, in order.
var syncSteps = []string{"google", "scope", "mapping", "templates", "safety", "review"}

// syncDraft is a wizard in progress.
type syncDraft struct {
	// Base is the settings version the draft started from (the save is
	// refused if another change came first).
	Base    int64
	S       syncapi.Settings
	Test    *syncapi.TestResult
	Preview *syncapi.PreviewResult
	Query   string
	Errors  []string
}

// maxKeyUpload bounds the service account key upload.
const maxKeyUpload = syncapi.MaxKeySize

// groupInfo is a referenced group as the administrator's AD shows it.
type groupInfo struct {
	Ref   string
	Name  string
	DN    string
	SID   string
	Found bool
}

// syncGroupNames resolves every group the settings reference (by SID or
// DN), for display. Failures leave the entry unresolved.
func (s *Server) syncGroupNames(ctx context.Context, rc *reqCtx, st syncapi.Settings) map[string]groupInfo {
	refs := append(append([]string(nil), st.Scope.IncludeGroups...), st.Scope.ExcludeGroups...)
	for _, r := range st.Mapping.OrgUnits {
		if r.Group != "" {
			refs = append(refs, r.Group)
		}
	}
	out := map[string]groupInfo{}
	if len(refs) == 0 {
		return out
	}
	_ = rc.withConn(ctx, func(conn *ad.Conn) error {
		for _, ref := range refs {
			if _, done := out[ref]; done {
				continue
			}
			out[ref] = lookupGroupRef(ctx, conn, ref)
		}
		return nil
	})
	return out
}

func lookupGroupRef(ctx context.Context, conn *ad.Conn, ref string) groupInfo {
	gi := groupInfo{Ref: ref}
	var f escape.Filter
	if strings.HasPrefix(strings.ToUpper(ref), "S-1-") {
		sd, err := sid.Parse(strings.ToUpper(ref))
		if err != nil {
			return gi
		}
		f = escape.And(groupFilter, escape.EqBytes("objectSid", sd.Bytes()))
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: f, Attributes: ad.GroupAttributes, Limit: 1}) {
			if err != nil {
				return gi
			}
			g := ad.GroupFromEntry(e)
			return groupInfo{Ref: ref, Name: g.Name, DN: g.DN, SID: g.SID.String(), Found: true}
		}
		return gi
	}
	e, err := conn.Get(ctx, ref, ad.GroupAttributes...)
	if err != nil {
		return gi
	}
	g := ad.GroupFromEntry(e)
	return groupInfo{Ref: ref, Name: g.Name, DN: g.DN, SID: g.SID.String(), Found: true}
}

// draft returns the session's draft, starting one from the current
// settings when there is none.
func (s *Server) syncDraftFor(ctx context.Context, rc *reqCtx) (*syncDraft, *syncapi.ConfigView, error) {
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		return nil, nil, err
	}
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	if rc.sess.syncDraft == nil {
		rc.sess.syncDraft = &syncDraft{Base: cfg.Version, S: cfg.Settings}
	}
	return rc.sess.syncDraft, &cfg, nil
}

func (rc *reqCtx) setupStep() string {
	st := rc.r.URL.Query().Get("step")
	if st == "" {
		st = rc.form("step")
	}
	if !slices.Contains(syncSteps, st) {
		return syncSteps[0]
	}
	return st
}

func setupURL(step string) string { return "/admin/sync/setup?step=" + step }

// nextStep follows the "next" button of a step form.
func (rc *reqCtx) afterStep(step string) {
	if rc.form("go") == "next" {
		if i := slices.Index(syncSteps, step); i >= 0 && i+1 < len(syncSteps) {
			step = syncSteps[i+1]
		}
	}
	rc.redirect(setupURL(step))
}

// groupHit is one group search result.
type groupHit struct {
	Name, DN, SID, Description string
}

func (s *Server) handleSyncSetup(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	step := rc.setupStep()
	d := map[string]any{"Step": step, "Steps": syncSteps}
	dr, cfg, err := s.syncDraftFor(ctx, rc)
	if err != nil {
		d["Error"] = s.syncErr(rc, err)
		rc.render(http.StatusOK, "sync_setup", d)
		return
	}
	d["D"], d["C"] = dr, cfg
	if dr.Base != cfg.Version {
		d["Stale"] = true
	}
	var st syncapi.Status
	if err := s.syncCall(ctx, rc, syncapi.OpStatus, nil, &st); err == nil {
		d["Key"] = st.Key
	}
	d["Groups"] = s.syncGroupNames(ctx, rc, dr.S)
	q := strings.TrimSpace(rc.r.URL.Query().Get("q"))
	d["Q"] = q
	switch step {
	case "scope", "mapping":
		err := rc.withConn(ctx, func(conn *ad.Conn) error {
			opts, err := ouOptions(ctx, conn)
			if err != nil {
				return err
			}
			d["OUs"] = opts
			labels := map[string]string{}
			for _, o := range opts {
				labels[strings.ToLower(o.DN)] = o.Label
			}
			d["OULabels"] = labels
			if q == "" {
				return nil
			}
			var hits []groupHit
			for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: andFilters(groupFilter, searchFilter(q, "sAMAccountName", "cn", "description")),
				Attributes: ad.GroupAttributes, SortBy: "cn", Limit: 20}) {
				if err != nil {
					return err
				}
				g := ad.GroupFromEntry(e)
				hits = append(hits, groupHit{Name: g.Name, DN: g.DN, SID: g.SID.String(), Description: g.Description})
			}
			d["Hits"] = hits
			return nil
		})
		if err != nil {
			s.log.Warn("sync setup: directory read failed", "err", err)
			d["DirError"] = rc.T(s.adErrorKey(err))
		}
	case "templates":
		d["AttrFields"] = []string{"title", "department", "employee_id", "phone_work", "phone_mobile"}
	case "review":
		var v syncapi.ConfigValidateResult
		if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: dr.S}, &v); err != nil {
			d["Error"] = s.syncErr(rc, err)
		} else {
			d["V"] = v
		}
	}
	rc.render(http.StatusOK, "sync_setup", d)
}

// withDraft runs fn on the session's draft and redirects.
func (s *Server) withDraft(rc *reqCtx, fn func(dr *syncDraft) (step string, errKey string)) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	dr, _, err := s.syncDraftFor(ctx, rc)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync")
		return
	}
	rc.sess.mu.Lock()
	step, errKey := fn(dr)
	dr.Errors = nil
	rc.sess.mu.Unlock()
	if errKey != "" {
		rc.flashErr(errKey)
		rc.redirect(setupURL(step))
		return
	}
	rc.afterStep(step)
}

// lines splits a textarea into trimmed, non-empty lines.
func lines(s string) []string {
	out := []string{}
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// words splits a list typed with commas, spaces or new lines.
func words(s string) []string {
	out := []string{}
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if w = strings.TrimSpace(w); w != "" {
			out = append(out, w)
		}
	}
	return out
}

func (s *Server) handleSyncSetupGoogle(rc *reqCtx) {
	s.withDraft(rc, func(dr *syncDraft) (string, string) {
		dr.S.Google.AdminSubject = rc.form("admin_subject")
		if c := rc.form("customer"); c != "" {
			dr.S.Google.Customer = c
		}
		old := slices.Clone(dr.S.Mapping.AllowedDomains)
		dr.S.Mapping.AllowedDomains = words(strings.ToLower(rc.form("domains")))
		// Group domains follow the user domains unless set apart.
		if slices.Equal(dr.S.Mapping.GroupAllowedDomains, old) {
			dr.S.Mapping.GroupAllowedDomains = slices.Clone(dr.S.Mapping.AllowedDomains)
		}
		return "google", ""
	})
}

func (s *Server) handleSyncSetupTest(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	dr, _, err := s.syncDraftFor(ctx, rc)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync")
		return
	}
	rc.sess.mu.Lock()
	settings := dr.S
	rc.sess.mu.Unlock()
	var res syncapi.TestResult
	if err := s.syncCall(ctx, rc, syncapi.OpConnectionTest, syncapi.ConnectionTestParams{Settings: &settings}, &res); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(setupURL("google"))
		return
	}
	rc.sess.mu.Lock()
	dr.Test = &res
	rc.sess.mu.Unlock()
	result := "ok"
	if !res.AD.OK || !res.Google.OK {
		result = "failed"
	}
	s.audit(ctx, rc, "sync.connection_test", "google", fmt.Sprintf("ad=%v google=%v", res.AD.OK, res.Google.OK), result)
	rc.redirect(setupURL("google"))
}

// keyFile is the non-secret part of a service account key file.
type keyFile struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
}

func (s *Server) handleSyncSetupKey(rc *reqCtx) {
	f, _, err := rc.r.FormFile("key")
	if err != nil {
		rc.flashErr("sync.key.err_missing")
		rc.redirect(setupURL("google"))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyUpload+1))
	_ = f.Close()
	var k keyFile
	if err != nil || len(raw) > maxKeyUpload || json.Unmarshal(raw, &k) != nil || k.Type != "service_account" || k.ClientEmail == "" || k.PrivateKey == "" {
		rc.flashErr("sync.key.err_invalid")
		rc.redirect(setupURL("google"))
		return
	}
	// The preview names the key; the key itself is never shown, logged or
	// audited, and lives only in this pending operation until confirmed.
	preview := fmt.Sprintf("conductor-sync %s\nclient_email: %s\nkey_id: %s\n# %s", syncapi.OpKeySet, k.ClientEmail, k.PrivateKeyID, rc.T("sync.key.preview"))
	keyJSON := string(raw)
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.key_set", target: k.ClientEmail, reauth: true,
		title: rc.T("sync.key.title"), summary: rc.T("sync.key.summary"), preview: preview,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.syncCall(ctx, rc, syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: keyJSON}, &syncapi.KeyInfo{})
		},
		back: setupURL("google"), done: rc.T("sync.key.done")})
}

func validDN(dn string) bool {
	_, err := escape.ParseDN(dn)
	return err == nil && strings.TrimSpace(dn) != ""
}

func validSID(s string) bool {
	_, err := sid.Parse(s)
	return err == nil
}

func removeFold(list []string, v string) []string {
	return slices.DeleteFunc(slices.Clone(list), func(x string) bool { return strings.EqualFold(x, v) })
}

func addUnique(list []string, v string) []string {
	if slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) }) {
		return list
	}
	return append(slices.Clone(list), v)
}

func (s *Server) handleSyncSetupScope(rc *reqCtx) {
	s.withDraft(rc, func(dr *syncDraft) (string, string) {
		sc := &dr.S.Scope
		dn, ref := rc.form("dn"), rc.form("ref")
		switch rc.form("action") {
		case "add_base", "add_exclude_base", "add_group_base":
			if !validDN(dn) {
				return "scope", "sync.setup.err_dn"
			}
			switch rc.form("action") {
			case "add_base":
				sc.UserBases = addUnique(sc.UserBases, dn)
			case "add_exclude_base":
				sc.ExcludeBases = addUnique(sc.ExcludeBases, dn)
			default:
				sc.GroupBases = addUnique(sc.GroupBases, dn)
			}
		case "remove_base":
			sc.UserBases = removeFold(sc.UserBases, dn)
		case "remove_exclude_base":
			sc.ExcludeBases = removeFold(sc.ExcludeBases, dn)
		case "remove_group_base":
			sc.GroupBases = removeFold(sc.GroupBases, dn)
		case "include", "exclude":
			if !validSID(ref) && !validDN(ref) {
				return "scope", "sync.setup.err_group"
			}
			if rc.form("action") == "include" {
				sc.ExcludeGroups = removeFold(sc.ExcludeGroups, ref)
				sc.IncludeGroups = addUnique(sc.IncludeGroups, ref)
			} else {
				sc.IncludeGroups = removeFold(sc.IncludeGroups, ref)
				sc.ExcludeGroups = addUnique(sc.ExcludeGroups, ref)
			}
		case "remove_group":
			sc.IncludeGroups = removeFold(sc.IncludeGroups, ref)
			sc.ExcludeGroups = removeFold(sc.ExcludeGroups, ref)
		case "save":
			sc.ExpiredAsDisabled = rc.form("expired_as_disabled") == "1"
		default:
			return "scope", "form.invalid"
		}
		return "scope", ""
	})
}

func (s *Server) handleSyncSetupMapping(rc *reqCtx) {
	s.withDraft(rc, func(dr *syncDraft) (string, string) {
		m := &dr.S.Mapping
		target := rc.form("target")
		switch rc.form("action") {
		case "add_group_rule":
			ref := rc.form("ref")
			prio, err := strconv.Atoi(rc.form("priority"))
			if (!validSID(ref) && !validDN(ref)) || err != nil || prio < 1 || prio > 1000 || !strings.HasPrefix(target, "/") {
				return "mapping", "sync.setup.err_rule"
			}
			m.OrgUnits = append(slices.Clone(m.OrgUnits), syncapi.OrgUnitRule{Group: ref, Target: target, Priority: prio})
		case "add_ou_rule":
			dn := rc.form("dn")
			if !validDN(dn) || !strings.HasPrefix(target, "/") {
				return "mapping", "sync.setup.err_rule"
			}
			m.OrgUnits = append(slices.Clone(m.OrgUnits), syncapi.OrgUnitRule{AD: dn, Target: target})
		case "remove_rule":
			i, err := strconv.Atoi(rc.form("index"))
			if err != nil || i < 0 || i >= len(m.OrgUnits) {
				return "mapping", "form.invalid"
			}
			m.OrgUnits = slices.Delete(slices.Clone(m.OrgUnits), i, i+1)
		case "default":
			if !strings.HasPrefix(rc.form("default_org_unit"), "/") {
				return "mapping", "sync.setup.err_rule"
			}
			m.DefaultOrgUnit = rc.form("default_org_unit")
		default:
			return "mapping", "form.invalid"
		}
		return "mapping", ""
	})
}

func (s *Server) handleSyncSetupTemplates(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	dr, _, err := s.syncDraftFor(ctx, rc)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync")
		return
	}
	rc.sess.mu.Lock()
	m := &dr.S.Mapping
	m.PrimaryEmail = lines(rc.rawForm("primary_email"))
	m.GivenName = lines(rc.rawForm("given_name"))
	m.FamilyName = lines(rc.rawForm("family_name"))
	m.GroupEmail = lines(rc.rawForm("group_email"))
	m.GroupName = lines(rc.rawForm("group_name"))
	m.GroupDescription = lines(rc.rawForm("group_description"))
	m.GroupAllowedDomains = words(strings.ToLower(rc.form("group_domains")))
	attrs := map[string]string{}
	for _, f := range []string{"title", "department", "employee_id", "phone_work", "phone_mobile"} {
		if v := rc.form("attr_" + f); v != "" {
			attrs[f] = v
		}
	}
	m.Attributes = attrs
	dr.Query = rc.form("q")
	settings := dr.S
	rc.sess.mu.Unlock()
	if rc.form("go") != "preview" {
		rc.afterStep("templates")
		return
	}
	// Preview against real users, with the draft (nothing is stored).
	var res syncapi.PreviewResult
	if err := s.syncCall(ctx, rc, syncapi.OpMappingPreview, syncapi.MappingPreviewParams{Settings: &settings, Query: rc.form("q"), Limit: 15}, &res); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(setupURL("templates"))
		return
	}
	rc.sess.mu.Lock()
	dr.Preview = &res
	rc.sess.mu.Unlock()
	rc.redirect(setupURL("templates") + "#preview")
}

func (s *Server) handleSyncSetupSafety(rc *reqCtx) {
	s.withDraft(rc, func(dr *syncDraft) (string, string) {
		bad := false
		num := func(name string) int {
			n, err := strconv.Atoi(rc.form(name))
			if err != nil {
				bad = true
			}
			return n
		}
		pct := func(name string) float64 {
			f, err := strconv.ParseFloat(rc.form(name), 64)
			if err != nil {
				bad = true
			}
			return f
		}
		l := syncapi.LimitSettings{MaxCreates: num("max_creates"), MaxSuspends: num("max_suspends"), MaxUnsuspends: num("max_unsuspends"),
			MaxRenames: num("max_renames"), MaxUpdates: num("max_updates"), MaxGroupChanges: num("max_group_changes"),
			MaxMembershipChanges: num("max_membership_changes"), MaxTouchedPercent: pct("max_touched_percent"),
			MinSourceUsers: num("min_source_users"), MaxSourceDropPercent: pct("max_source_drop_percent")}
		if bad {
			return "safety", "sync.setup.err_number"
		}
		dr.S.Limits = l
		dr.S.Policy.SuspendDisabled = rc.form("suspend_disabled") == "1"
		dr.S.Policy.CreateDisabled = rc.form("create_disabled") == "1"
		dr.S.Policy.RemoveUnmanagedMembers = rc.form("remove_unmanaged") == "1"
		if a := rc.form("adopt"); a == "never" || a == "email" {
			dr.S.Policy.Adopt = a
		}
		dr.S.Schedule.Interval = rc.form("interval")
		return "safety", ""
	})
}

func (s *Server) handleSyncSetupDiscard(rc *reqCtx) {
	rc.sess.mu.Lock()
	rc.sess.syncDraft = nil
	rc.sess.mu.Unlock()
	rc.flashOK("sync.setup.discarded")
	rc.redirect("/admin/sync")
}

// handleSyncSetupSave validates the draft with conductor-sync and proposes
// the new version (re-authentication required).
func (s *Server) handleSyncSetupSave(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	dr, cfg, err := s.syncDraftFor(ctx, rc)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync")
		return
	}
	rc.sess.mu.Lock()
	settings, base := dr.S, dr.Base
	rc.sess.mu.Unlock()
	if base != cfg.Version {
		rc.flashErr("sync.setup.stale")
		rc.redirect(setupURL("review"))
		return
	}
	var v syncapi.ConfigValidateResult
	if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: settings}, &v); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(setupURL("review"))
		return
	}
	if !v.Valid {
		rc.flashErr("sync.setup.invalid")
		rc.redirect(setupURL("review"))
		return
	}
	if len(v.Changes) == 0 && base != 0 {
		rc.flashOK("form.no_change")
		rc.redirect(setupURL("review"))
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conductor-sync %s\nbase_version: %d\n", syncapi.OpConfigUpdate, base)
	for _, c := range v.Changes {
		fmt.Fprintf(&b, "%s\n", c.String())
	}
	comment := clipName(rc.form("comment"))
	if comment != "" {
		fmt.Fprintf(&b, "# %s\n", comment)
	}
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.config_update", target: "google", reauth: true,
		title: rc.T("sync.setup.save_title"), summary: rc.T("sync.setup.save_summary", len(v.Changes)), preview: strings.TrimRight(b.String(), "\n"),
		run: func(ctx context.Context, rc *reqCtx) error {
			var res syncapi.ConfigUpdateResult
			if err := s.syncCall(ctx, rc, syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: base, Settings: settings, Comment: comment}, &res); err != nil {
				return err
			}
			rc.sess.mu.Lock()
			rc.sess.syncDraft = nil
			rc.sess.mu.Unlock()
			return nil
		},
		back: "/admin/sync/config", done: rc.T("sync.setup.saved")})
}
