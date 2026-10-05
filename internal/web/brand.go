package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/i18n"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Branding of the self-service pages (/me and below). Level 1 is the
// document edited in Settings > Branding (stored here, versioned, and
// pushed to conductor-idp for its sign-in pages); level 2 the template
// directory read at startup. Admin pages always keep the product look and
// the built-in partials.

//go:embed templates/brand/*.html
var brandFS embed.FS

// brandState is the current level 1 branding.
type brandState struct {
	version int64
	doc     branding.Branding
	css     []byte
	cssTag  string
	assets  map[string]store.BrandingAsset
}

// overridable partials and their contract.
var partialSpecs = []struct {
	name, file, doc string
	required        []string
}{
	{"brand-header", "header.html", "page header: logo, organization name and the signed-in user",
		[]string{`data-e2e="nav-link-home"`, `href="/"`, `data-e2e="nav-text-user"`}},
	{"brand-footer", "footer.html", "page footer: footer text, links, support contact, language and theme",
		[]string{`data-e2e="footer-link-lang-en"`, `data-e2e="footer-link-lang-pt-br"`, `data-e2e="footer-link-theme-light"`,
			`data-e2e="footer-link-theme-dark"`, `data-e2e="footer-link-theme-system"`}},
	{"self-home", "self-home.html", "the self-service home (/me): account, contact details and their actions",
		[]string{`data-e2e="me-text-sam"`, `data-e2e="me-link-password"`, `href="/me/password"`, `data-e2e="me-link-security"`,
			`href="/me/security"`, `data-e2e="me-link-edit"`, `href="/me/edit"`}},
}

// BuiltinPartials returns the overridable partials with their built-in
// bodies (`conductor templates show|list`).
func BuiltinPartials() []branding.Partial {
	var out []branding.Partial
	for _, p := range partialSpecs {
		src, err := brandFS.ReadFile("templates/brand/" + p.file)
		if err != nil {
			panic("web: missing built-in partial " + p.file)
		}
		out = append(out, branding.Partial{Name: p.name, File: p.file, Source: string(src), Required: p.required, Doc: p.doc})
	}
	return out
}

// samplePage is the data an override is checked with.
func (s *Server) samplePage() pageData {
	u := ad.User{DisplayName: "Sample User", SAMAccountName: "sample", UserPrincipalName: "sample@example.com", Mail: "sample@example.com"}
	return pageData{Lang: "en", CSRF: "sample-csrf", User: &userInfo{Name: "Sample User", SAM: "sample", Roles: []string{"admin"}},
		Nav: map[string]bool{"accounts": true}, Path: "/me", Query: url.Values{}, Version: s.version, B: branding.SampleView(),
		D: map[string]any{"U": u, "Fields": fieldViews(selfFields, u)}}
}

// renderPartial renders a candidate partial body with the sample data.
func (s *Server) renderPartial(p branding.Partial, body string) (string, error) {
	t, err := template.New("").Funcs(s.funcs("en")).ParseFS(templateFS, "templates/partials.html")
	if err != nil {
		return "", err
	}
	if _, err := t.Parse(branding.Define(p.Name, body)); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, p.Name, s.samplePage()); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// loadOverrides reads the template directory and logs what it decided.
func (s *Server) loadOverrides() branding.Result {
	res := branding.Load(s.cfg.Branding.TemplatesDir, BuiltinPartials(), s.allowed, s.renderPartial)
	for _, f := range res.Findings {
		if f.Level == branding.LevelOK {
			s.log.Info("branding template", "file", f.File, "result", f.Message)
		} else {
			s.log.Warn("branding template", "file", f.File, "level", f.Level, "result", f.Message)
		}
	}
	return res
}

// CheckTemplates checks the template directory of a configuration
// (`conductor templates check`).
func CheckTemplates(cfg *config.Config) ([]branding.Finding, error) {
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, cat: cat, version: "check", allowed: cfg.AllowedOrigins()}
	return branding.Check(cfg.Branding.TemplatesDir, BuiltinPartials(), s.allowed, s.renderPartial), nil
}

func assetURL(a branding.Asset) string { return "/branding/assets/" + a.SHA256 }

func tag(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// applyBranding makes a version current.
func (s *Server) applyBranding(version int64, doc branding.Branding, assets []store.BrandingAsset) {
	st := &brandState{version: version, doc: doc, assets: map[string]store.BrandingAsset{}}
	for _, a := range assets {
		st.assets[a.SHA256] = a
	}
	st.css = []byte(branding.CSS(doc, branding.PageScope, assetURL))
	st.cssTag = tag(st.css)
	s.brand.Store(st)
}

// errBrandingStored marks a stored document that no longer validates.
var errBrandingStored = errors.New("web: the stored branding is not valid")

// readBranding reads the current version and its images from the store
// (version 0 and the zero document when it was never saved).
func (s *Server) readBranding(ctx context.Context) (int64, branding.Branding, []store.BrandingAsset, error) {
	row, err := s.store.CurrentBranding(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return 0, branding.Branding{}, nil, nil
	}
	if err != nil {
		return 0, branding.Branding{}, nil, err
	}
	var doc branding.Branding
	if err := json.Unmarshal([]byte(row.Data), &doc); err != nil || doc.Validate() != nil {
		return row.Version, branding.Branding{}, nil, errBrandingStored
	}
	assets, err := s.store.BrandingAssets(ctx, doc.AssetHashes())
	if err != nil {
		return row.Version, branding.Branding{}, nil, err
	}
	return row.Version, doc, assets, nil
}

// loadBranding makes the stored branding current; a failure keeps the
// product look (logged): it must never stop the portal.
func (s *Server) loadBranding(ctx context.Context) {
	s.applyBranding(0, branding.Branding{}, nil)
	v, doc, assets, err := s.readBranding(ctx)
	if err != nil {
		s.log.Error("branding: using the product look", "version", v, "err", err)
		return
	}
	s.applyBranding(v, doc, assets)
}

// branded reports whether the page is part of the self-service portal.
func (rc *reqCtx) branded() bool {
	p := rc.r.URL.Path
	return p == "/me" || strings.HasPrefix(p, "/me/")
}

// brandView is the page's {{.B}}, or nil for the product look.
func (rc *reqCtx) brandView() *branding.View {
	if !rc.branded() {
		return nil
	}
	st := rc.s.brand.Load()
	if st == nil || st.doc.IsZero() && len(rc.s.overridden) == 0 && rc.s.customCSS == nil {
		return nil
	}
	u := branding.URLs{CSS: "/branding/theme.css?v=" + st.cssTag, Asset: assetURL}
	if rc.s.customCSS != nil {
		u.CustomCSS = "/branding/custom.css?v=" + rc.s.customTag
	}
	return branding.NewView(st.doc, rc.lang, "Samba Conductor", u)
}

// brandRoutes registers the generated stylesheet, the custom stylesheet
// and the images of the current branding.
func (s *Server) brandRoutes() {
	s.mux.HandleFunc("GET /branding/theme.css", func(w http.ResponseWriter, r *http.Request) {
		st := s.brand.Load()
		s.serveVersioned(w, r, "text/css; charset=utf-8", st.css, st.cssTag)
	})
	s.mux.HandleFunc("GET /branding/custom.css", func(w http.ResponseWriter, r *http.Request) {
		if s.customCSS == nil {
			s.securityHeaders(w.Header())
			http.NotFound(w, r)
			return
		}
		s.serveVersioned(w, r, "text/css; charset=utf-8", s.customCSS, s.customTag)
	})
	s.mux.HandleFunc("GET /branding/assets/{sha}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.brand.Load().assets[r.PathValue("sha")]
		serveAsset(s, w, r, a, ok, "public, max-age=31536000, immutable")
	})
}

// serveAsset writes a stored image with its type, under the strict
// security headers; a current image is cached for good (its URL is its
// digest), a draft's never.
func serveAsset(s *Server, w http.ResponseWriter, r *http.Request, a store.BrandingAsset, ok bool, cache string) {
	s.securityHeaders(w.Header())
	if !ok || !slices.Contains([]string{branding.TypePNG, branding.TypeJPEG, branding.TypeWebP, branding.TypeICO}, a.ContentType) {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.ContentType)
	h.Set("Cache-Control", cache)
	h.Set("ETag", `"`+a.SHA256+`"`)
	if r.Header.Get("If-None-Match") == `"`+a.SHA256+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(a.Data)
}

// serveVersioned serves a generated file: cached for long when the URL
// names its current version, revalidated otherwise.
func (s *Server) serveVersioned(w http.ResponseWriter, r *http.Request, ctype string, body []byte, version string) {
	s.securityHeaders(w.Header())
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("ETag", `"`+version+`"`)
	if r.URL.Query().Get("v") == version {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == `"`+version+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

// parsePage parses one page with the layout, the shared partials and the
// overridable partials ("product-<name>": built-in; "<name>": chosen).
func (s *Server) parsePage(lang, file string, bodies map[string]string) (*template.Template, error) {
	t, err := template.New("").Funcs(s.funcs(lang)).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", file)
	if err != nil {
		return nil, err
	}
	for _, p := range BuiltinPartials() {
		if _, err := t.Parse(branding.Define("product-"+p.Name, p.Source)); err != nil {
			return nil, err
		}
		body, ok := bodies[p.Name]
		if !ok {
			body = p.Source
		}
		if _, err := t.Parse(branding.Define(p.Name, body)); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// pageNames lists the page templates.
func pageNames() ([]string, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		base := strings.TrimSuffix(path.Base(n), ".html")
		if base != "layout" && base != "partials" {
			out = append(out, n)
		}
	}
	return out, nil
}
