package web

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
)

func pngOf(w, h int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h)))
	return buf.Bytes()
}

// postBranding sends the branding form with files (field -> content).
func (h *harness) postBranding(t *testing.T, tok string, fields url.Values, files map[string][]byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf", h.csrfOf(tok))
	for k, vals := range fields {
		for _, v := range vals {
			_ = mw.WriteField(k, v)
		}
	}
	for field, content := range files {
		fw, _ := mw.CreateFormFile(field, field+".bin")
		_, _ = fw.Write(content)
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", "https://"+testHost+"/admin/branding", &buf)
	r.RemoteAddr = "192.0.2.10:40000"
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	return w
}

func brandingFields() url.Values {
	return url.Values{"org_name": {"Example Org"}, "primary_color": {"#1D4ED8"}, "accent_color": {"#f59e0b"},
		"signin_title_en": {"Sign in to Example"}, "notice_en": {"Maintenance on Saturday"}, "notice_pt-BR": {"Manutenção no sábado"},
		"help_en": {"Forgot it? Call us."}, "footer_en": {"Example IT"}, "support_email": {"help@example.com"},
		"support_phone": {"+1 555 0100"}, "link_password_policy": {"https://example.com/pw"}, "link_terms": {"tel:+15550100"}}
}

func mustContainAll(t *testing.T, what, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Fatalf("%s lacks %q:\n%.1500s", what, w, body)
		}
	}
}

func TestBrandingEditPreviewSaveRevert(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	user := h.session(t, "normal.user", stageFull, false)

	page := h.do("GET", "/admin/branding", admin, nil).Body.String()
	mustContainAll(t, "edit page", page, `data-e2e="nav-link-branding"`, `data-e2e="branding-form"`, `data-e2e="branding-text-version"`,
		`enctype="multipart/form-data"`, `data-e2e="branding-file-logo-light"`, `data-e2e="branding-badge-in-sync"`)

	// Edit: the form becomes a draft and its preview.
	logo, icon := pngOf(120, 30), pngOf(32, 32)
	w := h.postBranding(t, admin, brandingFields(), map[string][]byte{"file_logo_light": logo, "file_favicon": icon})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/branding/preview" {
		t.Fatalf("draft: %d %s", w.Code, w.Body.String())
	}
	pv := h.do("GET", "/admin/branding/preview", admin, nil).Body.String()
	mustContainAll(t, "preview", pv, `data-e2e="branding-preview-light"`, `data-e2e="branding-preview-dark"`, "Sign in to Example",
		`href="/admin/branding/preview.css?t=`, `org_name: (empty) -&gt; &#34;Example Org&#34;`, "image logo_light", `data-e2e="branding-btn-save"`)
	css := h.do("GET", "/admin/branding/preview.css", admin, nil)
	mustContainAll(t, "preview css", css.Body.String(), ".brand-preview {", "--accent: #1d4ed8", ".brand-preview.preview-dark {")
	logoSHA := branding.Digest(logo)
	da := h.do("GET", "/admin/branding/draft-asset?sha="+logoSHA, admin, nil)
	if da.Code != http.StatusOK || da.Header().Get("Content-Type") != "image/png" || da.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("draft asset: %d %v", da.Code, da.Header())
	}
	// Nothing is live before the confirmation.
	if v := h.s.brand.Load().version; v != 0 || fi.branding.Version != 0 {
		t.Fatal("applied before saving")
	}

	// Save: password and a fresh second factor.
	loc := h.do("POST", "/admin/branding/save", admin, nil).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	st := h.s.brand.Load()
	if st.version != 1 || st.doc.OrgName != "Example Org" || st.doc.PrimaryColor != "#1d4ed8" {
		t.Fatalf("saved %+v", st)
	}
	if fi.branding.Version != 1 || len(fi.brandingAssets) != 2 || fi.branding.Branding.OrgName != "Example Org" {
		t.Fatalf("pushed %+v", fi.branding)
	}
	audit := h.auditText(t)
	mustContainAll(t, "audit", audit, "branding.save branding [re-authenticated]", "branding.version branding version=1 base=0",
		"branding.push conductor-idp version=1")

	// The self-service pages are branded; the admin pages are not.
	me := h.do("GET", "/me/password", user, nil)
	body := me.Body.String()
	mustContainAll(t, "self-service", body, "Example Org", `href="/branding/theme.css?v=`, `src="/branding/assets/`+logoSHA+`"`,
		`data-e2e="brand-text-notice">Maintenance on Saturday`, `data-e2e="me-password-link-policy"`, `href="mailto:help@example.com"`,
		`href="tel:&#43;15550100"`, `data-e2e="brand-text-footer">Example IT`, `type="image/png"`)
	if csp := me.Header().Get("Content-Security-Policy"); csp != cspPolicy {
		t.Fatalf("CSP changed on a branded page: %s", csp)
	}
	adminPage := h.do("GET", "/admin", admin, nil).Body.String()
	if strings.Contains(adminPage, "Example Org") || strings.Contains(adminPage, "/branding/theme.css") || strings.Contains(adminPage, "Maintenance on") {
		t.Fatal("admin page branded")
	}
	// Portuguese texts, English fallback.
	pt := h.do("GET", "/me/password?lang=pt-BR", user, nil).Body.String()
	mustContainAll(t, "pt-BR", pt, "Manutenção no sábado", "Example IT")

	// Public, same-origin, typed and cached files.
	tc := h.do("GET", "/branding/theme.css?v="+st.cssTag, "", nil)
	if tc.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(tc.Header().Get("Cache-Control"), "immutable") ||
		!strings.Contains(tc.Body.String(), "--brand-accent: #f59e0b") {
		t.Fatalf("theme.css %v", tc.Header())
	}
	img := h.do("GET", "/branding/assets/"+logoSHA, "", nil)
	if img.Code != http.StatusOK || img.Header().Get("Content-Type") != "image/png" || img.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!bytes.Equal(img.Body.Bytes(), logo) {
		t.Fatalf("asset %d %v", img.Code, img.Header())
	}

	// A second version without the favicon, then a revert to version 1.
	f2 := brandingFields()
	f2.Set("org_name", "Example Two")
	f2.Set("remove_favicon", "1")
	h.postBranding(t, admin, f2, nil)
	loc = h.do("POST", "/admin/branding/save", admin, nil).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if st := h.s.brand.Load(); st.version != 2 || st.doc.OrgName != "Example Two" || len(st.doc.Assets) != 1 || len(fi.brandingAssets) != 1 {
		t.Fatalf("v2 %+v", st)
	}
	vs := h.do("GET", "/admin/branding/versions", admin, nil).Body.String()
	mustContainAll(t, "versions", vs, `data-e2e="branding-row-1"`, `data-e2e="branding-row-2"`, `data-e2e="branding-btn-revert-1"`,
		`data-e2e="branding-btn-reset"`)
	loc = h.do("POST", "/admin/branding/revert", admin, url.Values{"version": {"1"}}).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	st = h.s.brand.Load()
	if st.version != 3 || st.doc.OrgName != "Example Org" || len(st.doc.Assets) != 2 || fi.branding.Version != 3 || len(fi.brandingAssets) != 2 {
		t.Fatalf("revert %+v", st)
	}
	row, _ := h.st.GetBrandingVersion(context.Background(), 3)
	if row.RevertedFrom != 1 || row.CreatedBy != "lab.admin" {
		t.Fatalf("row %+v", row)
	}
	// Back to the product look.
	loc = h.do("POST", "/admin/branding/revert", admin, url.Values{"version": {"0"}}).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if st := h.s.brand.Load(); st.version != 4 || !st.doc.IsZero() || !fi.branding.Branding.IsZero() {
		t.Fatalf("reset %+v", st)
	}
	if body := h.do("GET", "/me/password", user, nil).Body.String(); strings.Contains(body, "/branding/") || strings.Contains(body, "Example") {
		t.Fatal("still branded after the reset")
	}
}

func TestBrandingValidation(t *testing.T) {
	h, _ := ssoHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	cases := map[string]struct {
		set   map[string]string
		files map[string][]byte
		want  string
	}{
		"contrast": {set: map[string]string{"primary_color": "#ffcc00"}, want: "4.5:1"},
		"color":    {set: map[string]string{"primary_color": "blue"}, want: "#rrggbb"},
		"js link":  {set: map[string]string{"link_help": "javascript:alert(1)"}, want: "https address"},
		"http":     {set: map[string]string{"support_url": "http://help.example.com"}, want: "https address"},
		"email":    {set: map[string]string{"support_email": "nobody"}, want: "not an e-mail address"},
		"long":     {set: map[string]string{"org_name": strings.Repeat("x", 101)}, want: "too long"},
		"svg":      {files: map[string][]byte{"file_logo_light": []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)}, want: "SVG images are not accepted"},
		"type":     {files: map[string][]byte{"file_favicon": []byte("GIF89a......")}, want: "not an accepted image"},
		"size":     {files: map[string][]byte{"file_favicon": bytes.Repeat([]byte{0}, 70<<10)}, want: "larger than 64 KiB"},
	}
	for name, c := range cases {
		f := brandingFields()
		for k, v := range c.set {
			f.Set(k, v)
		}
		w := h.postBranding(t, admin, f, c.files)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.want) || !strings.Contains(w.Body.String(), `data-e2e="branding-alert-problems"`) {
			t.Errorf("%s: %d %.600s", name, w.Code, w.Body.String())
		}
	}
	if h.s.sess.byID[hashToken(admin)].brandDraft != nil {
		t.Fatal("a refused form left a draft")
	}
	if !strings.Contains(h.auditText(t), "branding.draft branding refused") {
		t.Fatal("refusals not audited")
	}
	// A pale accent is only a warning, shown on the preview.
	f := brandingFields()
	f.Set("accent_color", "#f4f4f4")
	if w := h.postBranding(t, admin, f, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("warning blocked the draft: %d", w.Code)
	}
	mustContainAll(t, "preview", h.do("GET", "/admin/branding/preview", admin, nil).Body.String(), `data-e2e="branding-alert-warnings"`, "below 3:1")
}

// TestBrandingOnlyAdmins: helpdesk, auditors and users never reach the
// branding pages (TestRouteGuards covers every route; this one the nav).
func TestBrandingOnlyAdmins(t *testing.T) {
	h := newHarness(t)
	for _, u := range []string{"helpdesk.user", "auditor.user", "normal.user"} {
		tok := h.session(t, u, stageFull, true)
		if w := h.do("GET", "/admin/branding", tok, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", u, w.Code)
		}
		if strings.Contains(h.do("GET", "/me/password", tok, nil).Body.String(), "nav-link-branding") {
			t.Errorf("%s sees the branding entry", u)
		}
	}
}

// A failed push keeps the saved version and offers to send it again.
func TestBrandingPushFailure(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	fi.fail[idpapi.OpBrandingUpdate] = &idpapi.Error{Code: idpapi.CodeBadRequest, Message: `operation "branding.update" is not allowlisted`}
	h.postBranding(t, admin, brandingFields(), nil)
	loc := h.do("POST", "/admin/branding/save", admin, nil).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if h.s.brand.Load().version != 1 {
		t.Fatal("not saved")
	}
	page := h.do("GET", "/admin/branding", admin, nil).Body.String()
	mustContainAll(t, "after a failed push", page, "does not support branding", `data-e2e="branding-btn-push"`)
	if !strings.Contains(h.auditText(t), "branding.push conductor-idp version=1 error:") {
		t.Fatal("failed push not audited")
	}
	delete(fi.fail, idpapi.OpBrandingUpdate)
	loc = h.do("POST", "/admin/branding/push", admin, nil).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if fi.branding.Version != 1 {
		t.Fatalf("push again: %+v", fi.branding)
	}
	if !strings.Contains(h.do("GET", "/admin/branding", admin, nil).Body.String(), `data-e2e="branding-badge-in-sync"`) {
		t.Fatal("still out of sync")
	}
}

// Two edits from the same version: the second save is refused.
func TestBrandingStaleEdit(t *testing.T) {
	h, _ := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	a1 := h.session(t, "lab.admin", stageFull, true)
	a2 := h.session(t, "lab.admin", stageFull, true)
	h.postBranding(t, a1, brandingFields(), nil)
	f := brandingFields()
	f.Set("org_name", "Other")
	h.postBranding(t, a2, f, nil)
	loc1 := h.do("POST", "/admin/branding/save", a1, nil).Header().Get("Location")
	loc2 := h.do("POST", "/admin/branding/save", a2, nil).Header().Get("Location")
	h.confirmWith(t, a1, loc1, secret)
	h.confirmWith(t, a2, loc2, secret)
	if st := h.s.brand.Load(); st.version != 1 || st.doc.OrgName != "Example Org" {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(h.auditText(t), "branding.save branding") || !strings.Contains(h.auditText(t), "branding.err.stale") {
		t.Fatal("stale save not audited")
	}
}

func TestBrandingAllowedOriginsOnlyOnSelfService(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Branding.AllowedOrigins = []string{"https://cdn.example.com"} })
	h.s.applyBranding(1, branding.Branding{OrgName: "Example Org"}, nil)
	user := h.session(t, "normal.user", stageFull, false)
	csp := h.do("GET", "/me/password", user, nil).Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' https://cdn.example.com;") || !strings.Contains(csp, "font-src 'self' https://cdn.example.com;") ||
		!strings.Contains(csp, "script-src 'none'") {
		t.Fatalf("branded CSP: %s", csp)
	}
	admin := h.session(t, "lab.admin", stageFull, true)
	if strings.Contains(h.do("GET", "/admin/users", admin, nil).Header().Get("Content-Security-Policy"), "cdn.example.com") {
		t.Fatal("allowlist on an admin page")
	}
	// The second-factor pages keep their nonce policy.
	sec := h.do("GET", "/me/security", user, nil).Header().Get("Content-Security-Policy")
	if !strings.Contains(sec, "script-src 'nonce-") || !strings.Contains(sec, "cdn.example.com") {
		t.Fatalf("security page CSP: %s", sec)
	}
}

func TestSelfServiceOverrides(t *testing.T) {
	dir := t.TempDir()
	parts := BuiltinPartials()
	header := strings.Replace(parts[0].Source, `<span>{{if .B}}{{.B.Name}}`, `<span class="org-header">{{if .B}}{{.B.Name}}`, 1)
	if err := os.WriteFile(filepath.Join(dir, "header.html"), []byte(parts[0].Header()+"\n"+header), 0o644); err != nil {
		t.Fatal(err)
	}
	// A self-service home that drops the contract is refused.
	if err := os.WriteFile(filepath.Join(dir, "self-home.html"), []byte(`<h1>{{t "me.title"}}</h1>`), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *config.Config) { c.Branding.TemplatesDir = dir })
	if len(h.s.overridden) != 1 || h.s.overridden[0] != "brand-header" {
		t.Fatalf("overridden %v", h.s.overridden)
	}
	user := h.session(t, "normal.user", stageFull, false)
	if body := h.do("GET", "/me/password", user, nil).Body.String(); !strings.Contains(body, `class="org-header"`) {
		t.Fatal("override not used on a self-service page")
	}
	admin := h.session(t, "lab.admin", stageFull, true)
	if body := h.do("GET", "/admin/users", admin, nil).Body.String(); strings.Contains(body, "org-header") {
		t.Fatal("override used on an admin page")
	}
	fs, err := CheckTemplates(h.s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	levels := map[string]string{}
	for _, f := range fs {
		levels[f.File] = f.Level
	}
	if levels["header.html"] != branding.LevelOK || levels["self-home.html"] != branding.LevelError {
		t.Fatalf("%v", fs)
	}
	// Every built-in partial meets its own contract.
	for _, p := range parts {
		out, err := h.s.renderPartial(p, p.Source)
		if err != nil {
			t.Fatal(err)
		}
		if issues := branding.CheckOutput(out, p.Required, nil); len(issues) > 0 {
			t.Errorf("%s: %v", p.Name, issues)
		}
	}
}

// An override that fails on a real page falls back to the built-in one.
func TestSelfServiceOverrideRuntimeFallback(t *testing.T) {
	dir := t.TempDir()
	parts := BuiltinPartials()
	// The sample has .D.Fields; a page without them fails on len.
	header := strings.Replace(parts[0].Source, "<span>", `<span data-x="{{len .D.Fields}}">`, 1)
	_ = os.WriteFile(filepath.Join(dir, "header.html"), []byte(header), 0o644)
	h := newHarness(t, func(c *config.Config) { c.Branding.TemplatesDir = dir })
	if len(h.s.overridden) != 1 {
		t.Fatalf("override refused: %v", h.s.overridden)
	}
	user := h.session(t, "normal.user", stageFull, false)
	w := h.do("GET", "/me/password", user, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "data-x") || !strings.Contains(w.Body.String(), `data-e2e="nav-link-home"`) {
		t.Fatalf("%d %.300s", w.Code, w.Body.String())
	}
}

func TestBrandingStoredAcrossRestart(t *testing.T) {
	h := newHarness(t)
	logo := pngOf(50, 20)
	a, _ := branding.Inspect(branding.SlotLogoLight, logo)
	doc := branding.Branding{OrgName: "Example Org", Assets: map[string]branding.Asset{branding.SlotLogoLight: a}}
	data, _ := json.Marshal(doc)
	if _, err := h.st.SaveBranding(context.Background(), 0, string(data), doc.AssetHashes(),
		[]store.BrandingAsset{{SHA256: a.SHA256, ContentType: a.Type, Data: logo}}, "lab.admin", 0); err != nil {
		t.Fatal(err)
	}
	h.s.loadBranding(context.Background())
	if st := h.s.brand.Load(); st.version != 1 || st.doc.OrgName != "Example Org" || !bytes.Equal(st.assets[a.SHA256].Data, logo) {
		t.Fatalf("%+v", st)
	}
}

// The built-in partials' messages exist (TestI18nKeysExist reads the
// page templates only), and so do the dynamic branding messages.
func TestBrandingMessages(t *testing.T) {
	h := newHarness(t)
	keyRE := regexp.MustCompile(`(?:\{\{|\()t "([a-zA-Z0-9_.]+)"`)
	for _, p := range BuiltinPartials() {
		for _, m := range keyRE.FindAllStringSubmatch(p.Source, -1) {
			if !h.s.cat.Has(m[1]) {
				t.Errorf("%s: missing %q", p.File, m[1])
			}
		}
	}
	keys := []string{"branding.preview.mode.light", "branding.preview.mode.dark"}
	for _, s := range branding.Slots {
		keys = append(keys, "branding.field."+s)
	}
	for _, c := range []string{branding.CodeTooLong, branding.CodeControl, branding.CodeColor, branding.CodeContrast, branding.CodeAccent,
		branding.CodeURL, branding.CodeEmail, branding.CodePhone, branding.CodeLanguage, branding.CodeSlot, branding.CodeAsset, branding.CodeSVG,
		branding.CodeImageType, branding.CodeImageSize, branding.CodeImageDims, branding.CodeImageCorrupt, branding.CodeTooManyAssets} {
		keys = append(keys, "branding.problem."+c)
	}
	for _, f := range []string{"org_name", "primary_color", "accent_color", "texts", "assets", "signin_title", "signin_note", "help", "footer",
		"notice", "support_email", "support_phone", "support_url", "link_help", "link_terms", "link_privacy", "link_password_policy"} {
		keys = append(keys, "branding.field."+f)
	}
	for _, k := range keys {
		if !h.s.cat.Has(k) {
			t.Errorf("missing %q", k)
		}
	}
}
