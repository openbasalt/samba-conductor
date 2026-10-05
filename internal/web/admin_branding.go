package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Settings > Branding: the level 1 branding of the user-facing pages
// (conductor's self-service and conductor-idp's sign-in pages).
// Administrators only. An edit becomes a draft in the session, is
// previewed (light and dark, with the contrast warnings), then saved as a
// new version after the password and a fresh second factor; the version
// is pushed to conductor-idp. Every version is kept (the newest
// store.KeepBrandingVersions) and any of them can be restored the same
// way. Every step is audited.

// brandingMaxBody bounds the edit form: the four images at their limits
// plus the texts.
const brandingMaxBody = 2<<20 + 128<<10

// brandDraft is an edit waiting for its preview and confirmation.
type brandDraft struct {
	// base is the version the edit started from (optimistic
	// concurrency: a save on top of another version is refused).
	base int64
	doc  branding.Branding
	// blobs are the bytes of every image the draft references.
	blobs    map[string][]byte
	warnings []branding.Problem
	created  time.Time
}

// brandingError is a branding failure with a message key.
type brandingError struct {
	key string
	err error
}

func (e *brandingError) Error() string {
	if e.err != nil {
		return e.key + ": " + e.err.Error()
	}
	return e.key
}

func (e *brandingError) Unwrap() error { return e.err }

// slotView describes an image slot on the form.
type slotView struct {
	Slot   string
	URL    string
	Asset  *branding.Asset
	Accept string
	Types  string
	MaxKiB int
}

func (s *Server) slotViews(doc branding.Branding, url func(branding.Asset) string) []slotView {
	var out []slotView
	for _, slot := range branding.Slots {
		v := slotView{Slot: slot, Accept: strings.Join(branding.Types(slot), ","), MaxKiB: branding.MaxBytes(slot) >> 10}
		var short []string
		for _, t := range branding.Types(slot) {
			short = append(short, strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(t, "image/"), "x-")))
		}
		v.Types = strings.Join(short, ", ")
		if slot == branding.SlotFavicon {
			v.Accept += ",.ico"
		}
		if a, ok := doc.Assets[slot]; ok {
			a := a
			v.Asset, v.URL = &a, url(a)
		}
		out = append(out, v)
	}
	return out
}

func draftAssetURL(a branding.Asset) string { return "/admin/branding/draft-asset?sha=" + a.SHA256 }

// brandingPage renders the edit form for doc with the page's context.
func (s *Server) brandingPage(ctx context.Context, rc *reqCtx, status int, doc branding.Branding, fromDraft bool, problems []string) {
	st := s.brand.Load()
	url := assetURL
	if fromDraft {
		url = draftAssetURL
	}
	d := map[string]any{"B": doc, "Version": st.version, "Langs": branding.Languages, "Slots": s.slotViews(doc, url),
		"FromDraft": fromDraft, "Problems": problems, "IDP": s.idp != nil, "CanSSO": rc.roles.Has(PermSSORead)}
	if rc.sess != nil {
		rc.sess.mu.Lock()
		d["HasDraft"] = rc.sess.brandDraft != nil
		rc.sess.mu.Unlock()
	}
	if s.idp != nil {
		var v idpapi.BrandingView
		if err := s.idpCall(ctx, rc, idpapi.OpBrandingGet, nil, &v); err != nil {
			d["IDPError"] = s.brandingIDPErr(rc, err)
		} else {
			d["IDPVersion"], d["IDPAt"] = v.Version, v.UpdatedAt
			d["InSync"] = v.Version == st.version
		}
		var sv idpapi.SettingsView
		if err := s.idpCall(ctx, rc, idpapi.OpSettingsGet, nil, &sv); err == nil {
			d["Consent"] = sv.Settings.ConsentText
		}
	}
	rc.render(status, "branding", d)
}

func (s *Server) handleBranding(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	doc := s.brand.Load().doc
	fromDraft := false
	if rc.r.URL.Query().Get("draft") == "1" {
		rc.sess.mu.Lock()
		if dr := rc.sess.brandDraft; dr != nil {
			doc, fromDraft = dr.doc, true
		}
		rc.sess.mu.Unlock()
	}
	s.brandingPage(ctx, rc, http.StatusOK, doc, fromDraft, nil)
}

// formBranding reads the texts, colors, contact and links of the form.
func formBranding(rc *reqCtx) branding.Branding {
	v := func(k string) string { return rc.r.PostFormValue(k) }
	b := branding.Branding{OrgName: v("org_name"), PrimaryColor: v("primary_color"), AccentColor: v("accent_color"),
		Support: branding.Support{Email: v("support_email"), Phone: v("support_phone"), URL: v("support_url")},
		Links: branding.Links{Help: v("link_help"), Terms: v("link_terms"), Privacy: v("link_privacy"),
			PasswordPolicy: v("link_password_policy")},
		Texts: map[string]branding.Texts{}, Assets: map[string]branding.Asset{}}
	for _, l := range branding.Languages {
		b.Texts[l] = branding.Texts{SignInTitle: v("signin_title_" + l), SignInNote: v("signin_note_" + l), Help: v("help_" + l),
			Footer: v("footer_" + l), Notice: v("notice_" + l)}
	}
	return b
}

// handleBrandingDraft turns the form into a draft and opens its preview.
func (s *Server) handleBrandingDraft(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	st := s.brand.Load()
	start, blobs := st.doc, map[string][]byte{}
	for h, a := range st.assets {
		blobs[h] = a.Data
	}
	fromDraft := rc.r.PostFormValue("from_draft") == "1"
	rc.sess.mu.Lock()
	if dr := rc.sess.brandDraft; fromDraft && dr != nil {
		start = dr.doc
		for h, b := range dr.blobs {
			blobs[h] = b
		}
	}
	rc.sess.mu.Unlock()
	doc := formBranding(rc)
	for slot, a := range start.Assets {
		doc.Assets[slot] = a
	}
	var problems []branding.Problem
	for _, slot := range branding.Slots {
		if rc.r.PostFormValue("remove_"+slot) == "1" {
			delete(doc.Assets, slot)
			continue
		}
		data, ok, err := uploadedFile(rc, "file_"+slot, branding.MaxBytes(slot))
		if err != nil {
			problems = append(problems, branding.Problem{Field: slot, Code: branding.CodeImageSize, Arg: fmt.Sprint(branding.MaxBytes(slot)>>10) + " KiB"})
			continue
		}
		if !ok {
			continue
		}
		a, err := branding.Inspect(slot, data)
		var se *branding.SlotError
		if errors.As(err, &se) {
			problems = append(problems, se.Problem())
			continue
		}
		if err != nil {
			problems = append(problems, branding.Problem{Field: slot, Code: branding.CodeImageCorrupt})
			continue
		}
		doc.Assets[slot], blobs[a.SHA256] = a, data
	}
	doc = doc.Normalize()
	all := append(problems, doc.Check()...)
	if errs := branding.Errors(all); len(errs) > 0 {
		// The images shown again are the ones the edit started from: the
		// uploads of a refused form are not kept.
		doc.Assets = start.Assets
		fromDraft = fromDraft && rc.brandDraft() != nil
		s.audit(ctx, rc, "branding.draft", "branding", "refused: "+problemList(errs), store.ResultDenied)
		s.brandingPage(ctx, rc, http.StatusBadRequest, doc, fromDraft, s.problemTexts(rc, errs))
		return
	}
	keep := map[string][]byte{}
	for _, h := range doc.AssetHashes() {
		keep[h] = blobs[h]
	}
	var warnings []branding.Problem
	for _, p := range all {
		if p.Warning {
			warnings = append(warnings, p)
		}
	}
	rc.sess.mu.Lock()
	rc.sess.brandDraft = &brandDraft{base: st.version, doc: doc, blobs: keep, warnings: warnings, created: s.now()}
	rc.sess.mu.Unlock()
	rc.redirect("/admin/branding/preview")
}

// uploadedFile reads a file field (ok=false when none was chosen).
func uploadedFile(rc *reqCtx, field string, max int) ([]byte, bool, error) {
	f, hdr, err := rc.r.FormFile(field)
	if err != nil {
		return nil, false, nil
	}
	defer func() { _ = f.Close() }()
	if hdr.Size == 0 {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > max {
		return nil, false, errors.New("too large")
	}
	return data, true, nil
}

func problemList(ps []branding.Problem) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return strings.Join(out, "; ")
}

// problemTexts translates problems: "<field>: <message>".
func (s *Server) problemTexts(rc *reqCtx, ps []branding.Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, s.fieldLabel(rc, p.Field)+": "+rc.T("branding.problem."+p.Code, p.Arg))
	}
	return out
}

// fieldLabel names a form field ("signin_note_pt-BR" is the sign-in note
// in Portuguese).
func (s *Server) fieldLabel(rc *reqCtx, field string) string {
	for _, l := range branding.Languages {
		if base, ok := strings.CutSuffix(field, "_"+l); ok {
			return rc.T("branding.field."+base) + " (" + rc.T("sso.lang."+l) + ")"
		}
	}
	return rc.T("branding.field." + field)
}

func (rc *reqCtx) brandDraft() *brandDraft {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	d := rc.sess.brandDraft
	if d != nil && rc.s.now().Sub(d.created) > 2*time.Hour {
		rc.sess.brandDraft = nil
		return nil
	}
	return d
}

func (s *Server) handleBrandingPreview(rc *reqCtx) {
	dr := rc.brandDraft()
	if dr == nil {
		rc.redirect("/admin/branding")
		return
	}
	cur := s.brand.Load()
	views := map[string]*branding.View{}
	for _, l := range branding.Languages {
		views[l] = branding.NewView(dr.doc, l, "Samba Conductor", branding.URLs{Asset: draftAssetURL})
	}
	changes := brandingDiff(cur.doc, dr.doc)
	rc.render(http.StatusOK, "branding_preview", map[string]any{"PV": views[rc.lang], "Views": views, "Langs": branding.Languages,
		"Warnings": s.problemTexts(rc, dr.warnings), "Changes": changes, "NoChange": len(changes) == 0,
		"Stale": cur.version != dr.base, "ExtraCSS": "/admin/branding/preview.css?t=" + tag([]byte(branding.CSS(dr.doc, branding.PreviewScope, draftAssetURL)))})
}

// handleBrandingPreviewCSS serves the draft's stylesheet, scoped to the
// preview cards.
func (s *Server) handleBrandingPreviewCSS(rc *reqCtx) {
	dr := rc.brandDraft()
	css := ""
	if dr != nil {
		css = branding.CSS(dr.doc, branding.PreviewScope, draftAssetURL)
	}
	rc.w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = rc.w.Write([]byte(css))
}

// handleBrandingDraftAsset serves an image of the draft.
func (s *Server) handleBrandingDraftAsset(rc *reqCtx) {
	dr := rc.brandDraft()
	sha := rc.r.URL.Query().Get("sha")
	// A draft is private to this session: never cached.
	if dr != nil {
		for _, a := range dr.doc.Assets {
			if a.SHA256 == sha {
				serveAsset(s, rc.w, rc.r, store.BrandingAsset{SHA256: sha, ContentType: a.Type, Data: dr.blobs[sha]}, dr.blobs[sha] != nil, "no-store")
				return
			}
		}
	}
	serveAsset(s, rc.w, rc.r, store.BrandingAsset{}, false, "no-store")
}

func (s *Server) handleBrandingDiscard(rc *reqCtx) {
	rc.sess.mu.Lock()
	rc.sess.brandDraft = nil
	rc.sess.mu.Unlock()
	rc.flashOK("branding.discarded")
	rc.redirect("/admin/branding")
}

// handleBrandingSave proposes the draft as a new version.
func (s *Server) handleBrandingSave(rc *reqCtx) {
	dr := rc.brandDraft()
	if dr == nil {
		rc.redirect("/admin/branding")
		return
	}
	changes := brandingDiff(s.brand.Load().doc, dr.doc)
	if len(changes) == 0 {
		rc.flashOK("form.no_change")
		rc.redirect("/admin/branding")
		return
	}
	warning := ""
	if len(dr.warnings) > 0 {
		warning = strings.Join(s.problemTexts(rc, dr.warnings), " ")
	}
	draft := *dr
	rc.propose(&pendingOp{perm: PermBranding, action: "branding.save", target: "branding", reauth: true,
		title: rc.T("branding.save.title"), summary: rc.T("branding.save.summary"), warning: warning,
		preview: fmt.Sprintf("branding: new version on top of %d\n%s", draft.base, strings.Join(changes, "\n")),
		run: func(ctx context.Context, rc *reqCtx) error {
			if err := s.commitBranding(ctx, rc, draft.base, draft.doc, draft.blobs, 0); err != nil {
				return err
			}
			rc.sess.mu.Lock()
			rc.sess.brandDraft = nil
			rc.sess.mu.Unlock()
			return nil
		}, back: "/admin/branding", done: rc.T("branding.saved")})
}

// commitBranding stores a new version, makes it current and pushes it to
// conductor-idp. A failed push leaves the version saved (the page offers
// to push again) and is reported and audited on its own.
func (s *Server) commitBranding(ctx context.Context, rc *reqCtx, base int64, doc branding.Branding, blobs map[string][]byte, revertedFrom int64) error {
	if err := doc.Validate(); err != nil {
		return &brandingError{key: "form.invalid", err: err}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var assets []store.BrandingAsset
	types := map[string]string{}
	for _, a := range doc.Assets {
		types[a.SHA256] = a.Type
	}
	for _, h := range doc.AssetHashes() {
		b, ok := blobs[h]
		if !ok || branding.Digest(b) != h {
			return &brandingError{key: "branding.err.image_missing"}
		}
		assets = append(assets, store.BrandingAsset{SHA256: h, ContentType: types[h], Data: b})
	}
	rc.sess.mu.Lock()
	by := rc.sess.sam
	rc.sess.mu.Unlock()
	v, err := s.store.SaveBranding(ctx, base, string(data), doc.AssetHashes(), assets, by, revertedFrom)
	if errors.Is(err, store.ErrStale) {
		return &brandingError{key: "branding.err.stale", err: err}
	}
	if err != nil {
		return err
	}
	s.applyBranding(v, doc, assets)
	s.audit(ctx, rc, "branding.version", "branding", fmt.Sprintf("version=%d base=%d reverted_from=%d", v, base, revertedFrom), store.ResultOK)
	if err := s.pushBranding(ctx, rc, v, doc, assets); err != nil {
		rc.sess.addFlash("error", rc.T("branding.err.push", s.brandingIDPErr(rc, err)))
	}
	return nil
}

// pushBranding sends a version to conductor-idp (nothing when the single
// sign-on section is off) and audits the outcome.
func (s *Server) pushBranding(ctx context.Context, rc *reqCtx, version int64, doc branding.Branding, assets []store.BrandingAsset) error {
	if s.idp == nil {
		return nil
	}
	p := idpapi.BrandingUpdateParams{Version: version, Branding: doc}
	for _, a := range assets {
		p.Assets = append(p.Assets, idpapi.BrandingAsset{SHA256: a.SHA256, Data: a.Data})
	}
	err := s.idpCall(ctx, rc, idpapi.OpBrandingUpdate, p, &idpapi.BrandingView{})
	res, detail := store.ResultOK, fmt.Sprintf("version=%d", version)
	if err != nil {
		res, detail = store.ResultFailed, detail+" error: "+err.Error()
	}
	s.audit(ctx, rc, "branding.push", "conductor-idp", detail, res)
	return err
}

// brandingIDPErr explains an API failure, naming an idp that predates
// branding.
func (s *Server) brandingIDPErr(rc *reqCtx, err error) string {
	var e *idpapi.Error
	if errors.As(err, &e) && e.Code == idpapi.CodeBadRequest && strings.Contains(e.Message, "not allowlisted") {
		return rc.T("branding.err.idp_too_old")
	}
	return s.idpErr(rc, err)
}

// handleBrandingPush sends the current version to conductor-idp again.
func (s *Server) handleBrandingPush(rc *reqCtx) {
	if s.idp == nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	st := s.brand.Load()
	rc.propose(&pendingOp{perm: PermBranding, action: "branding.push_again", target: "conductor-idp", reauth: true,
		title: rc.T("branding.push.title"), summary: rc.T("branding.push.summary", st.version),
		preview: fmt.Sprintf("conductor-idp branding.update\nversion: %d", st.version),
		run: func(ctx context.Context, rc *reqCtx) error {
			cur := s.brand.Load()
			var assets []store.BrandingAsset
			for _, h := range cur.doc.AssetHashes() {
				assets = append(assets, cur.assets[h])
			}
			if err := s.pushBranding(ctx, rc, cur.version, cur.doc, assets); err != nil {
				return &brandingError{key: "branding.err.push_failed", err: err}
			}
			return nil
		}, back: "/admin/branding", done: rc.T("branding.pushed")})
}

// versionView is a row of the history.
type versionView struct {
	store.BrandingVersion
	Name    string
	Primary string
	Accent  string
	Images  int
	Current bool
}

func (s *Server) handleBrandingVersions(rc *reqCtx) {
	vs, err := s.store.BrandingVersions(rc.ctx())
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	cur := s.brand.Load().version
	var rows []versionView
	for _, v := range vs {
		var doc branding.Branding
		_ = json.Unmarshal([]byte(v.Data), &doc)
		rows = append(rows, versionView{BrandingVersion: v, Name: doc.OrgName, Primary: doc.PrimaryColor, Accent: doc.AccentColor,
			Images: len(doc.Assets), Current: v.Version == cur})
	}
	rc.render(http.StatusOK, "branding_versions", map[string]any{"Rows": rows, "Current": cur, "Keep": store.KeepBrandingVersions})
}

// handleBrandingRevert proposes an older version (or, for version 0, the
// product look) as a new version.
func (s *Server) handleBrandingRevert(rc *reqCtx) {
	n, err := strconv.ParseInt(rc.form("version"), 10, 64)
	if err != nil || n < 0 {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	cur := s.brand.Load()
	var doc branding.Branding
	blobs := map[string][]byte{}
	if n > 0 {
		v, err := s.store.GetBrandingVersion(rc.ctx(), n)
		if err != nil {
			rc.errorPage(http.StatusNotFound, "err.not_found")
			return
		}
		if json.Unmarshal([]byte(v.Data), &doc) != nil || doc.Validate() != nil {
			rc.sess.addFlash("error", rc.T("branding.err.version_invalid"))
			rc.redirect("/admin/branding/versions")
			return
		}
		assets, err := s.store.BrandingAssets(rc.ctx(), doc.AssetHashes())
		if err != nil {
			rc.sess.addFlash("error", rc.T("branding.err.image_missing"))
			rc.redirect("/admin/branding/versions")
			return
		}
		for _, a := range assets {
			blobs[a.SHA256] = a.Data
		}
	}
	changes := brandingDiff(cur.doc, doc)
	if len(changes) == 0 {
		rc.flashOK("form.no_change")
		rc.redirect("/admin/branding/versions")
		return
	}
	base := cur.version
	summary := rc.T("branding.revert.summary", n)
	if n == 0 {
		summary = rc.T("branding.revert.summary_reset")
	}
	rc.propose(&pendingOp{perm: PermBranding, action: "branding.revert", target: "branding", reauth: true,
		title: rc.T("branding.revert.title"), summary: summary,
		preview: fmt.Sprintf("branding: restore version %d as a new version on top of %d\n%s", n, base, strings.Join(changes, "\n")),
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.commitBranding(ctx, rc, base, doc, blobs, n)
		}, back: "/admin/branding/versions", done: rc.T("branding.reverted")})
}

// brandingDiff lists what changes between two documents, one line per
// field (texts quoted and shortened; images by digest).
func brandingDiff(a, b branding.Branding) []string {
	var out []string
	str := func(field, x, y string) {
		if x != y {
			out = append(out, fmt.Sprintf("%s: %s -> %s", field, quoteShort(x), quoteShort(y)))
		}
	}
	str("org_name", a.OrgName, b.OrgName)
	str("primary_color", a.PrimaryColor, b.PrimaryColor)
	str("accent_color", a.AccentColor, b.AccentColor)
	for _, l := range branding.Languages {
		ta, tb := a.Texts[l], b.Texts[l]
		str("signin_title["+l+"]", ta.SignInTitle, tb.SignInTitle)
		str("signin_note["+l+"]", ta.SignInNote, tb.SignInNote)
		str("help["+l+"]", ta.Help, tb.Help)
		str("footer["+l+"]", ta.Footer, tb.Footer)
		str("notice["+l+"]", ta.Notice, tb.Notice)
	}
	str("support.email", a.Support.Email, b.Support.Email)
	str("support.phone", a.Support.Phone, b.Support.Phone)
	str("support.url", a.Support.URL, b.Support.URL)
	str("links.help", a.Links.Help, b.Links.Help)
	str("links.terms", a.Links.Terms, b.Links.Terms)
	str("links.privacy", a.Links.Privacy, b.Links.Privacy)
	str("links.password_policy", a.Links.PasswordPolicy, b.Links.PasswordPolicy)
	img := func(x branding.Asset, ok bool) string {
		if !ok {
			return "(none)"
		}
		return fmt.Sprintf("sha256:%s %s %dx%d %d bytes", x.SHA256[:12], x.Type, x.Width, x.Height, x.Size)
	}
	for _, slot := range branding.Slots {
		x, okx := a.Assets[slot]
		y, oky := b.Assets[slot]
		if okx != oky || x != y {
			out = append(out, fmt.Sprintf("image %s: %s -> %s", slot, img(x, okx), img(y, oky)))
		}
	}
	return out
}

func quoteShort(s string) string {
	if s == "" {
		return "(empty)"
	}
	r := []rune(s)
	if len(r) > 80 {
		s = string(r[:77]) + "..."
	}
	return strconv.Quote(s)
}
