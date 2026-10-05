package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
)

// ---- guided presets ----

func (s *Server) handleSSONew(rc *reqCtx) {
	rc.render(http.StatusOK, "sso_new", map[string]any{"Presets": idpapi.Presets})
}

// handleSSOPreset asks a preset's questions (GET) and opens the matching
// form prefilled with the answers (POST, or GET for presets without
// questions). Nothing is saved before the form's own review.
func (s *Server) handleSSOPreset(rc *reqCtx) {
	p, ok := idpapi.PresetByID(rc.r.PathValue("preset"))
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	if rc.r.Method == http.MethodGet && len(p.Params) > 0 {
		rc.render(http.StatusOK, "sso_preset", map[string]any{"P": p, "V": map[string]string{}})
		return
	}
	vals := map[string]string{}
	for _, q := range p.Params {
		vals[q.Key] = rc.form(q.Key)
	}
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	switch p.Kind {
	case idpapi.KindOIDC:
		in, err := p.Client(vals)
		if err != nil {
			rc.render(http.StatusBadRequest, "sso_preset", map[string]any{"P": p, "V": vals, "Error": rc.T("sso.preset.invalid", err.Error())})
			return
		}
		f := clientFormFrom(in)
		f.Preset = p.ID
		s.renderClientForm(ctx, rc, http.StatusOK, f, map[string]any{"PresetName": p.Name, "PresetID": p.ID})
	default:
		in, err := p.SP(vals)
		if err != nil {
			rc.render(http.StatusBadRequest, "sso_preset", map[string]any{"P": p, "V": vals, "Error": rc.T("sso.preset.invalid", err.Error())})
			return
		}
		f := spFormFrom(in)
		f.Preset = p.ID
		s.renderSPForm(ctx, rc, http.StatusOK, f, map[string]any{"PresetName": p.Name, "PresetID": p.ID})
	}
}

// ---- keys ----

func (s *Server) handleSSOKeys(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSSOWrite)}
	var k idpapi.Keys
	if err := s.idpCall(ctx, rc, idpapi.OpKeysList, nil, &k); err != nil {
		d["Error"] = s.idpErr(rc, err)
	} else {
		d["K"] = k
	}
	var st idpapi.Status
	if err := s.idpCall(ctx, rc, idpapi.OpStatus, nil, &st); err == nil {
		d["S"] = st
	}
	rc.render(http.StatusOK, "sso_keys", d)
}

func (s *Server) handleSSOKeysRotate(rc *reqCtx) {
	purpose := rc.form("purpose")
	immediate := rc.form("immediate") == "1"
	if purpose != idpapi.KeyOIDC && purpose != idpapi.KeySAML || immediate && purpose != idpapi.KeySAML {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	key := "sso.keys.rotate_" + purpose
	if immediate {
		key += "_now"
	}
	rc.propose(&pendingOp{perm: PermSSOWrite, action: "sso.key_rotate", target: purpose, reauth: true,
		title: rc.T(key + "_title"), summary: rc.T(key + "_summary"), warning: rc.T(key + "_warning"),
		preview: fmt.Sprintf("conductor-idp keys.rotate\npurpose: %s\nimmediate: %v", purpose, immediate),
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.idpCall(ctx, rc, idpapi.OpKeysRotate, idpapi.KeysRotateParams{Purpose: purpose, Immediate: immediate}, &idpapi.KeyRotated{})
		}, back: "/admin/sso/keys", done: rc.T("sso.keys.rotated")})
}

// handleSSOCert downloads a SAML signing certificate (public).
func (s *Server) handleSSOCert(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	var c idpapi.CertPEM
	if err := s.idpCall(ctx, rc, idpapi.OpKeysCert, idpapi.KeysCertParams{ID: rc.r.URL.Query().Get("id")}, &c); err != nil {
		rc.sess.addFlash("error", s.idpErr(rc, err))
		rc.redirect("/admin/sso/keys")
		return
	}
	rc.w.Header().Set("Content-Type", "application/x-pem-file")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-idp-saml-`+safeName(c.ID)+`.pem"`)
	_, _ = rc.w.Write([]byte(c.PEM))
}

func safeName(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return -1
	}, v)
}

// ---- policy (settings) ----

func (s *Server) handleSSOPolicy(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSSOWrite), "Policies": idpapi.MFAPolicies, "Languages": idpapi.Languages,
		"ConductorPolicy": s.cfg.MFA.Policy, "ConductorDelegated": s.cfg.DelegatedMFARequired(),
		"ConductorKeys": s.cfg.WebAuthn.Enabled() && s.cfg.WebAuthn.AdminRequired, "MFASocket": s.cfg.IDP.MFASocket}
	var v idpapi.SettingsView
	if err := s.idpCall(ctx, rc, idpapi.OpSettingsGet, nil, &v); err != nil {
		d["Error"] = s.idpErr(rc, err)
	} else {
		d["V"] = v
	}
	rc.render(http.StatusOK, "sso_policy", d)
}

func (s *Server) handleSSOPolicyPost(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	var cur idpapi.SettingsView
	if err := s.idpCall(ctx, rc, idpapi.OpSettingsGet, nil, &cur); err != nil {
		rc.sess.addFlash("error", s.idpErr(rc, err))
		rc.redirect("/admin/sso/policy")
		return
	}
	idle, err1 := strconv.Atoi(rc.form("session_idle_minutes"))
	abs, err2 := strconv.Atoi(rc.form("session_absolute_hours"))
	next := idpapi.Settings{SessionIdleMinutes: idle, SessionAbsoluteHours: abs, MFAPolicy: rc.form("mfa_policy"), ConsentText: map[string]string{}}
	if cur.MFAPolicyShared {
		// Not used with conductor's 2FA; keep what was there.
		next.MFAPolicy = cur.Settings.MFAPolicy
	}
	for _, l := range idpapi.Languages {
		if v := strings.TrimSpace(rc.r.PostFormValue("consent_" + l)); v != "" {
			next.ConsentText[l] = strings.ReplaceAll(v, "\r\n", "\n")
		}
	}
	if err := next.Validate(); err != nil || err1 != nil || err2 != nil {
		rc.render(http.StatusBadRequest, "sso_policy", map[string]any{"CanWrite": true, "Policies": idpapi.MFAPolicies,
			"Languages": idpapi.Languages, "V": cur, "Error": rc.T("sso.policy.invalid"), "ConductorPolicy": s.cfg.MFA.Policy,
			"MFASocket": s.cfg.IDP.MFASocket})
		return
	}
	lines := []string{"conductor-idp settings.update", fmt.Sprintf("base_version: %d", cur.Version),
		fmt.Sprintf("session_idle_minutes: %d -> %d", cur.Settings.SessionIdleMinutes, next.SessionIdleMinutes),
		fmt.Sprintf("session_absolute_hours: %d -> %d", cur.Settings.SessionAbsoluteHours, next.SessionAbsoluteHours)}
	if !cur.MFAPolicyShared {
		lines = append(lines, "mfa_policy: "+cur.Settings.MFAPolicy+" -> "+next.MFAPolicy)
	}
	for _, l := range idpapi.Languages {
		if cur.Settings.ConsentText[l] != next.ConsentText[l] {
			lines = append(lines, fmt.Sprintf("consent_text[%s]: %q", l, next.ConsentText[l]))
		}
	}
	rc.propose(&pendingOp{perm: PermSSOWrite, action: "sso.settings", target: "conductor-idp", reauth: true,
		title: rc.T("sso.policy.title"), summary: rc.T("sso.policy.summary"), preview: strings.Join(lines, "\n"),
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.idpCall(ctx, rc, idpapi.OpSettingsUpdate, idpapi.SettingsUpdateParams{BaseVersion: cur.Version, Settings: next}, &idpapi.SettingsView{})
		}, back: "/admin/sso/policy", done: rc.T("sso.saved")})
}

// ---- activity ----

// activityPage is the audit page size.
const activityPage = 50

func (s *Server) handleSSOActivity(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	q := rc.r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if !slices.Contains([]int{1, 7, 30, 90}, days) {
		days = 7
	}
	page := rc.pageParam()
	f := idpapi.AuditListParams{Actor: strings.TrimSpace(q.Get("actor")), Action: strings.TrimSpace(q.Get("action")),
		Target: strings.TrimSpace(q.Get("target")), Result: q.Get("result"), Offset: (page - 1) * activityPage, Limit: activityPage}
	if !slices.Contains([]string{"", "ok", "denied", "failed", "pending"}, f.Result) {
		f.Result = ""
	}
	d := map[string]any{"Days": days, "DayChoices": []int{1, 7, 30, 90}, "F": f, "Page": page}
	var a idpapi.Activity
	if err := s.idpCall(ctx, rc, idpapi.OpActivity, idpapi.ActivityParams{Days: days}, &a); err != nil {
		d["Error"] = s.idpErr(rc, err)
		rc.render(http.StatusOK, "sso_activity", d)
		return
	}
	d["A"] = a
	var pg idpapi.AuditPage
	if err := s.idpCall(ctx, rc, idpapi.OpAuditList, f, &pg); err == nil {
		d["Events"], d["More"] = pg.Events, pg.More
	}
	if q.Get("verify") == "1" {
		var v idpapi.AuditVerify
		if err := s.idpCall(ctx, rc, idpapi.OpAuditVerify, nil, &v); err == nil {
			d["Verify"] = v
		}
	}
	rc.render(http.StatusOK, "sso_activity", d)
}
