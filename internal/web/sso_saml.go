package web

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// SAML service providers: metadata import (a document, a file or an https
// URL that conductor-idp fetches once), the registration form, a mapping
// preview against a real user, enable/disable and removal.

// maxMetadataUpload bounds an uploaded metadata file.
const maxMetadataUpload = 1 << 20

func (s *Server) handleSSOSPs(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSSOWrite)}
	var list []idpapi.SP
	if err := s.idpCall(ctx, rc, idpapi.OpSPList, nil, &list); err != nil {
		d["Error"] = s.idpErr(rc, err)
	} else {
		d["SPs"] = list
	}
	var st idpapi.Status
	if err := s.idpCall(ctx, rc, idpapi.OpStatus, nil, &st); err == nil {
		d["S"] = st
	}
	rc.render(http.StatusOK, "sso_sps", d)
}

// spForm is the service provider form, posted back whole on every action.
type spForm struct {
	Edit                                              bool
	EntityID, Name, ACS, Format, Source, Attrs, Relay string
	SLOURL, SLOBinding                                string
	AllowAll, Encrypt, IdPInitiated, RequireMFA       bool
	EncCert, SignCert                                 string // base64 DER (from metadata)
	ClearEnc, ClearSign                               bool
	PreviewUser, Preset                               string
	Warnings                                          []string
	groupPick
}

func (rc *reqCtx) spForm() spForm {
	_ = rc.r.ParseForm()
	return spForm{Edit: rc.form("edit") == "1", EntityID: rc.form("entity_id"), Name: rc.form("name"), ACS: rc.form("acs_urls"),
		Format: rc.form("nameid_format"), Source: rc.form("nameid_source"), Attrs: rc.form("attributes"), Relay: rc.form("default_relay"),
		SLOURL: rc.form("slo_url"), SLOBinding: rc.form("slo_binding"), AllowAll: rc.form("allow_all") == "1",
		Encrypt: rc.form("encrypt") == "1", IdPInitiated: rc.form("idp_initiated") == "1", RequireMFA: rc.form("require_mfa") == "1",
		EncCert: rc.form("enc_cert"), SignCert: rc.form("sign_cert"), ClearEnc: rc.form("clear_enc") == "1",
		ClearSign: rc.form("clear_sign") == "1", PreviewUser: rc.form("preview_user"), Preset: rc.form("preset"),
		groupPick: rc.groupPick()}
}

// attributes parses "Name=source" lines.
func parseAttrs(v string) ([]idpapi.Attribute, error) {
	out := []idpapi.Attribute{}
	for _, l := range formLines(v) {
		name, source, ok := strings.Cut(l, "=")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%q", l)
		}
		out = append(out, idpapi.Attribute{Name: strings.TrimSpace(name), Source: strings.TrimSpace(source)})
	}
	return out, nil
}

func formatAttrs(a []idpapi.Attribute) string {
	var out []string
	for _, v := range a {
		out = append(out, v.Name+"="+v.Source)
	}
	return strings.Join(out, "\n")
}

func (f spForm) input() (idpapi.SPInput, error) {
	attrs, err := parseAttrs(f.Attrs)
	if err != nil {
		return idpapi.SPInput{}, err
	}
	in := idpapi.SPInput{EntityID: f.EntityID, Name: f.Name, ACSURLs: formLines(f.ACS), NameIDFormat: f.Format, NameIDSource: f.Source,
		Attributes: attrs, Groups: f.Groups, AllowAllUsers: f.AllowAll, EncryptAssertion: f.Encrypt, IdPInitiated: f.IdPInitiated,
		DefaultRelay: f.Relay, RequireMFA: f.RequireMFA, SLOURL: f.SLOURL, SLOBinding: f.SLOBinding}
	if in.SLOURL == "" {
		in.SLOBinding = ""
	}
	if f.EncCert != "" {
		if in.EncryptionCert, err = base64.StdEncoding.DecodeString(f.EncCert); err != nil {
			return in, errors.New("encryption certificate")
		}
	}
	if f.SignCert != "" {
		if in.SigningCert, err = base64.StdEncoding.DecodeString(f.SignCert); err != nil {
			return in, errors.New("signing certificate")
		}
	}
	return in, nil
}

func spFormFrom(in idpapi.SPInput) spForm {
	f := spForm{EntityID: in.EntityID, Name: in.Name, ACS: strings.Join(in.ACSURLs, "\n"), Format: in.NameIDFormat, Source: in.NameIDSource,
		Attrs: formatAttrs(in.Attributes), Relay: in.DefaultRelay, SLOURL: in.SLOURL, SLOBinding: in.SLOBinding, AllowAll: in.AllowAllUsers,
		Encrypt: in.EncryptAssertion, IdPInitiated: in.IdPInitiated, RequireMFA: in.RequireMFA, groupPick: groupPick{Groups: slices.Clone(in.Groups)}}
	if len(in.EncryptionCert) > 0 {
		f.EncCert = base64.StdEncoding.EncodeToString(in.EncryptionCert)
	}
	if len(in.SigningCert) > 0 {
		f.SignCert = base64.StdEncoding.EncodeToString(in.SigningCert)
	}
	return f
}

func (s *Server) renderSPForm(ctx context.Context, rc *reqCtx, status int, f spForm, d map[string]any) {
	if d == nil {
		d = map[string]any{}
	}
	if f.Format == "" {
		f.Format = idpapi.NameIDFormats[0]
	}
	if f.Source == "" {
		f.Source = "email"
	}
	d["F"], d["Formats"], d["NameIDSources"], d["Sources"], d["SLOBindings"] = f, idpapi.NameIDFormats, idpapi.NameIDSources, idpapi.Sources, idpapi.SLOBindings
	if f.Edit {
		var sp idpapi.SP
		if err := s.idpCall(ctx, rc, idpapi.OpSPGet, idpapi.SPRef{EntityID: f.EntityID}, &sp); err == nil {
			d["SP"] = sp
		}
	}
	s.groupData(ctx, rc, f.groupPick, d)
	rc.render(status, "sso_sp_form", d)
}

func (s *Server) handleSSOSPNew(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	s.renderSPForm(ctx, rc, http.StatusOK, spForm{}, nil)
}

// handleSSOSPImport reads metadata (pasted, uploaded or by URL) through
// conductor-idp's parser and opens the form with what it found.
func (s *Server) handleSSOSPImport(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	p := idpapi.SPMetadataParams{XML: strings.TrimSpace(rc.r.FormValue("xml")), URL: strings.TrimSpace(rc.r.FormValue("url"))}
	if f, _, err := rc.r.FormFile("file"); err == nil {
		raw, err := io.ReadAll(io.LimitReader(f, maxMetadataUpload+1))
		_ = f.Close()
		if err != nil || len(raw) > maxMetadataUpload {
			rc.flashErr("sso.sp.metadata_too_large")
			rc.redirect("/admin/sso/saml/new")
			return
		}
		if len(raw) > 0 {
			p.XML, p.URL = string(raw), ""
		}
	}
	if p.XML != "" {
		p.URL = ""
	}
	if err := p.Validate(); err != nil {
		rc.flashErr("sso.sp.metadata_missing")
		rc.redirect("/admin/sso/saml/new")
		return
	}
	var d idpapi.SPDraft
	if err := s.idpCall(ctx, rc, idpapi.OpSPMetadata, p, &d); err != nil {
		rc.sess.addFlash("error", s.idpErr(rc, err))
		rc.redirect("/admin/sso/saml/new")
		return
	}
	s.audit(ctx, rc, "sso.sp_metadata", d.Input.EntityID, "imported "+map[bool]string{true: "from " + p.URL, false: "from a document"}[p.URL != ""], store.ResultOK)
	f := spFormFrom(d.Input)
	f.Name = rc.form("name")
	if f.Name == "" {
		if u, err := url.Parse(d.Input.EntityID); err == nil && u.Host != "" {
			f.Name = u.Host
		} else {
			f.Name = d.Input.EntityID
		}
	}
	f.Warnings = d.Warnings
	s.renderSPForm(ctx, rc, http.StatusOK, f, map[string]any{"Imported": true})
}

func (s *Server) handleSSOSPForm(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	f := rc.spForm()
	action := rc.form("action")
	if action != "preview" && action != "review" {
		s.renderSPForm(ctx, rc, http.StatusOK, f, nil)
		return
	}
	in, err := f.input()
	if err != nil {
		s.renderSPForm(ctx, rc, http.StatusBadRequest, f, map[string]any{"Error": rc.T("sso.sp.err_attributes", err.Error())})
		return
	}
	user := f.PreviewUser
	if user == "" {
		rc.sess.mu.Lock()
		user = rc.sess.sam
		rc.sess.mu.Unlock()
	}
	// The draft preview checks the input with conductor-idp's rules (the
	// registry), except the uniqueness of the entity ID.
	var pv idpapi.Preview
	if err := s.idpCall(ctx, rc, idpapi.OpSPPreview, idpapi.SPPreviewParams{Input: &in, Username: user}, &pv); err != nil {
		s.renderSPForm(ctx, rc, http.StatusBadRequest, f, map[string]any{"Error": s.idpErr(rc, err)})
		return
	}
	if action == "preview" {
		s.renderSPForm(ctx, rc, http.StatusOK, f, map[string]any{"Preview": pv})
		return
	}
	s.proposeSP(ctx, rc, f, in)
}

func certLine(der []byte) string {
	if len(der) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d bytes (DER)", len(der))
}

func (s *Server) proposeSP(ctx context.Context, rc *reqCtx, f spForm, in idpapi.SPInput) {
	names := s.groupNames(ctx, rc, in.Groups)
	var groups []string
	for _, g := range in.Groups {
		groups = append(groups, groupLabel(names, g))
	}
	op, action, title := idpapi.OpSPCreate, "sso.sp_create", rc.T("sso.sp.create_title", in.Name)
	if f.Edit {
		op, action, title = idpapi.OpSPUpdate, "sso.sp_update", rc.T("sso.sp.update_title", in.Name)
	}
	lines := []string{"conductor-idp " + string(op), "entity_id: " + in.EntityID, "name: " + in.Name,
		"acs_urls: " + strings.Join(in.ACSURLs, " "), "nameid: " + in.NameIDFormat + " <- " + in.NameIDSource,
		"attributes: " + strings.ReplaceAll(formatAttrs(in.Attributes), "\n", ", "), "allowed_groups: " + strings.Join(groups, ", "),
		fmt.Sprintf("allow_all_users: %v", in.AllowAllUsers), fmt.Sprintf("encrypt_assertion: %v", in.EncryptAssertion),
		"encryption_cert: " + certLine(in.EncryptionCert), fmt.Sprintf("idp_initiated: %v", in.IdPInitiated),
		"default_relay: " + in.DefaultRelay, fmt.Sprintf("require_mfa: %v", in.RequireMFA),
		"single_logout: " + in.SLOURL + " " + in.SLOBinding, "signing_cert: " + certLine(in.SigningCert)}
	if f.ClearEnc {
		lines = append(lines, "clear encryption_cert")
	}
	if f.ClearSign {
		lines = append(lines, "clear signing_cert")
	}
	warning := ""
	if in.AllowAllUsers {
		warning = rc.T("sso.warn.all_users")
	}
	back := "/admin/sso/saml/sp?id=" + url.QueryEscape(in.EntityID)
	rc.propose(&pendingOp{perm: PermSSOWrite, action: action, target: in.EntityID, reauth: true, title: title,
		summary: rc.T("sso.sp.summary"), warning: warning, preview: strings.Join(lines, "\n"), back: back, done: rc.T("sso.saved"),
		run: func(ctx context.Context, rc *reqCtx) error {
			if f.Edit {
				return s.idpCall(ctx, rc, idpapi.OpSPUpdate, idpapi.SPUpdateParams{EntityID: in.EntityID, Input: in,
					ClearEncryptionCert: f.ClearEnc, ClearSigningCert: f.ClearSign}, &idpapi.SP{})
			}
			return s.idpCall(ctx, rc, idpapi.OpSPCreate, idpapi.SPCreateParams{Input: in}, &idpapi.SP{})
		}})
}

func (s *Server) ssoSP(ctx context.Context, rc *reqCtx, id string) (idpapi.SP, bool) {
	var sp idpapi.SP
	if err := s.idpCall(ctx, rc, idpapi.OpSPGet, idpapi.SPRef{EntityID: id}, &sp); err != nil {
		var e *idpapi.Error
		if errors.As(err, &e) && (e.Code == idpapi.CodeNotFound || e.Code == idpapi.CodeBadRequest) || id == "" {
			rc.errorPage(http.StatusNotFound, "err.not_found")
		} else {
			rc.render(http.StatusOK, "sso_sp", map[string]any{"Error": s.idpErr(rc, err)})
		}
		return sp, false
	}
	return sp, true
}

// googleSP reports whether a registration is Google's (the page then
// lists what to enter in Google's Admin console).
func googleSP(sp idpapi.SP) bool {
	return strings.HasPrefix(sp.EntityID, "google.com") || strings.HasPrefix(sp.EntityID, "https://accounts.google.com/") ||
		slices.ContainsFunc(sp.ACSURLs, func(a string) bool {
			return strings.HasPrefix(a, "https://www.google.com/a/") || strings.HasPrefix(a, "https://accounts.google.com/")
		})
}

func (s *Server) handleSSOSP(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	sp, ok := s.ssoSP(ctx, rc, rc.r.URL.Query().Get("id"))
	if !ok {
		return
	}
	d := map[string]any{"SP": sp, "CanWrite": rc.roles.Has(PermSSOWrite), "Google": googleSP(sp)}
	var st idpapi.Status
	if err := s.idpCall(ctx, rc, idpapi.OpStatus, nil, &st); err == nil {
		d["S"] = st
	}
	d["GroupNames"] = s.groupNames(ctx, rc, sp.Groups)
	if u := strings.TrimSpace(rc.r.URL.Query().Get("preview_user")); u != "" {
		var pv idpapi.Preview
		if err := s.idpCall(ctx, rc, idpapi.OpSPPreview, idpapi.SPPreviewParams{EntityID: sp.EntityID, Username: u}, &pv); err != nil {
			d["PreviewError"] = s.idpErr(rc, err)
		} else {
			d["Preview"] = pv
		}
		d["PreviewUser"] = u
	}
	rc.render(http.StatusOK, "sso_sp", d)
}

func (s *Server) handleSSOSPEdit(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	sp, ok := s.ssoSP(ctx, rc, rc.r.URL.Query().Get("id"))
	if !ok {
		return
	}
	f := spFormFrom(sp.SPInput)
	// The registered certificates stay unless replaced or cleared.
	f.EncCert, f.SignCert = "", ""
	f.Edit = true
	s.renderSPForm(ctx, rc, http.StatusOK, f, nil)
}

func (s *Server) handleSSOSPEnabled(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	sp, ok := s.ssoSP(ctx, rc, rc.form("id"))
	if !ok {
		return
	}
	enable := rc.form("enabled") == "1"
	key := "sso.disable"
	if enable {
		key = "sso.enable"
	}
	rc.propose(&pendingOp{perm: PermSSOWrite, action: "sso.sp_enabled", target: sp.EntityID, reauth: true,
		title: rc.T(key+"_title", sp.Name), summary: rc.T(key + "_summary"),
		preview: fmt.Sprintf("conductor-idp sp.set_enabled\nentity_id: %s\nenabled: %v", sp.EntityID, enable),
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.idpCall(ctx, rc, idpapi.OpSPEnable, idpapi.SPEnableParams{EntityID: sp.EntityID, Enabled: enable}, &idpapi.SP{})
		}, back: "/admin/sso/saml/sp?id=" + url.QueryEscape(sp.EntityID), done: rc.T("sso.saved")})
}

func (s *Server) handleSSOSPDelete(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	sp, ok := s.ssoSP(ctx, rc, rc.form("id"))
	if !ok {
		return
	}
	back := "/admin/sso/saml/sp?id=" + url.QueryEscape(sp.EntityID)
	if rc.form("confirm") != sp.Name {
		s.audit(ctx, rc, "sso.sp_delete", sp.EntityID, "typed confirmation did not match", store.ResultDenied)
		rc.flashErr("sso.confirm_mismatch", sp.Name)
		rc.redirect(back)
		return
	}
	rc.propose(&pendingOp{perm: PermSSOWrite, action: "sso.sp_delete", target: sp.EntityID, reauth: true,
		title: rc.T("sso.delete_title", sp.Name), summary: rc.T("sso.sp.delete_summary"),
		preview: "conductor-idp sp.delete\nentity_id: " + sp.EntityID + "\nname: " + sp.Name,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.idpCall(ctx, rc, idpapi.OpSPDelete, idpapi.SPRef{EntityID: sp.EntityID}, nil)
		}, back: "/admin/sso/saml", done: rc.T("sso.deleted")})
}
