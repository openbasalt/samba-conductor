package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/conductor/internal/i18n"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pageData is what every template receives.
type pageData struct {
	Lang    string
	Theme   string
	CSRF    string
	User    *userInfo
	Nav     map[string]bool
	Flashes []flash
	Path    string
	Query   url.Values
	Version string
	// Nonce is set on the few pages that load the WebAuthn script (CSP
	// nonce); empty everywhere else, so no <script> is rendered.
	Nonce string
	// ScriptSRI is the Subresource Integrity hash of that script.
	ScriptSRI string
	// D is the page's own data.
	D map[string]any
}

type userInfo struct {
	Name  string
	SAM   string
	Roles []string
}

var e2eRE = regexp.MustCompile(`[^a-z0-9]+`)

// rightsKey turns an ACL rights name into a message key suffix.
var rightsKey = strings.NewReplacer(" ", "_", "(", "", ")", "")

// e2eID turns any value into a safe data-e2e suffix.
func e2eID(v any) string {
	s := strings.Trim(e2eRE.ReplaceAllString(strings.ToLower(fmt.Sprint(v)), "-"), "-")
	if s == "" {
		return "x"
	}
	return s
}

func (s *Server) funcs(lang string) template.FuncMap {
	return template.FuncMap{
		"t":   func(key string, args ...any) string { return s.cat.T(lang, key, args...) },
		"e2e": e2eID,
		"time": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"filetime": func(f ad.FileTime) string {
			t := f.Time()
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"rdn": func(dn string) string {
			_, v, err := escape.ParentDN(dn)
			if err != nil {
				return dn
			}
			return v
		},
		"parent": func(dn string) string {
			p, _, err := escape.ParentDN(dn)
			if err != nil {
				return ""
			}
			return p
		},
		"add": func(a, b int) int { return a + b },
		"qs": func(kv ...any) template.URL {
			v := url.Values{}
			for i := 0; i+1 < len(kv); i += 2 {
				if val := fmt.Sprint(kv[i+1]); val != "" && val != "0" {
					v.Set(fmt.Sprint(kv[i]), val)
				}
			}
			if len(v) == 0 {
				return "?"
			}
			return template.URL("?" + v.Encode())
		},
		"pageLink": func(q url.Values, page int) template.URL {
			v := url.Values{}
			for k, vals := range q {
				if k != "page" && k != "lang" && k != "theme" && len(vals) > 0 {
					v.Set(k, vals[0])
				}
			}
			if page > 1 {
				v.Set("page", fmt.Sprint(page))
			}
			return template.URL("?" + v.Encode())
		},
		"active": func(path, prefix string) bool {
			return path == prefix || (prefix != "/admin" && strings.HasPrefix(path, prefix+"/"))
		},
		// inSecurity: the pages of the Security entry of the sidebar.
		"inSecurity": func(path string) bool {
			for _, p := range []string{"/me/security", "/me/2fa", "/me/recovery-codes"} {
				if path == p || strings.HasPrefix(path, p+"/") {
					return true
				}
			}
			return false
		},
		"dnq":  func(dn string) template.URL { return template.URL(url.QueryEscape(dn)) },
		"join": strings.Join,
		"level": func(n int) string {
			names := []string{"2000", "2003 interim", "2003", "2008", "2008 R2", "2012", "2012 R2", "2016"}
			if n >= 0 && n < len(names) {
				return names[n]
			}
			return fmt.Sprint(n)
		},
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"langs": func() []string { return i18n.Languages },
		"days":  func(d time.Duration) int64 { return int64(d / (24 * time.Hour)) },
		"mins":  func(d time.Duration) int64 { return int64(d / time.Minute) },
		"ago": func(t time.Time) int64 {
			if t.IsZero() {
				return -1
			}
			return int64(s.now().Sub(t) / (24 * time.Hour))
		},
		"has": func(m map[string]bool, k string) bool { return m[k] },
		// File servers: the folder picker's links.
		"browse": func(srvID, p string) template.URL { return template.URL(browseLink(srvID, p)) },
		"pathq":  url.PathEscape,
		// rights names an ACL entry's rights (file or share), or keeps the
		// hex mask.
		"rights": func(r string) string {
			if key := "files.rights." + rightsKey.Replace(r); s.cat.Has(key) {
				return s.cat.T(lang, key)
			}
			return r
		},
		// Backups page: sizes and durations.
		"bytes": humanBytes,
		"dur":   shortDur,
		"ms":    func(n int64) string { return shortDur(time.Duration(n) * time.Millisecond) },
		"since": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return shortDur(s.now().Sub(t))
		},
	}
}

// pages are the templates under templates/ besides the shared ones.
func (s *Server) loadTemplates() (map[string]map[string]*template.Template, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]*template.Template{}
	for _, lang := range i18n.Languages {
		out[lang] = map[string]*template.Template{}
		for _, n := range names {
			base := strings.TrimSuffix(path.Base(n), ".html")
			if base == "layout" || base == "partials" {
				continue
			}
			t, err := template.New("").Funcs(s.funcs(lang)).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", n)
			if err != nil {
				return nil, fmt.Errorf("web: template %s: %w", n, err)
			}
			out[lang][base] = t
		}
	}
	return out, nil
}

// render executes a page into a buffer first, so a template error never
// sends half a page.
func (rc *reqCtx) render(status int, page string, d map[string]any) {
	t, ok := rc.s.tmpl[rc.lang][page]
	if !ok {
		rc.s.log.Error("unknown template", "page", page)
		http.Error(rc.w, "internal error", http.StatusInternalServerError)
		return
	}
	pd := pageData{Lang: rc.lang, Theme: rc.theme, Path: rc.r.URL.Path, Query: rc.r.URL.Query(), Version: rc.s.version, D: d, Nav: map[string]bool{},
		Nonce: rc.nonce}
	if rc.nonce != "" {
		pd.ScriptSRI = rc.s.scriptSRI
	}
	if rc.sess != nil {
		rc.sess.mu.Lock()
		pd.CSRF = rc.sess.csrf
		if rc.sess.stage == stageFull {
			pd.User = &userInfo{Name: rc.sess.displayName, SAM: rc.sess.sam, Roles: rc.roles.Names()}
		}
		rc.sess.mu.Unlock()
		pd.Flashes = rc.sess.takeFlashes()
		if pd.User != nil {
			for _, p := range allPerms {
				pd.Nav[string(p)] = rc.roles.Has(p)
			}
			pd.Nav["admin"] = rc.roles.Privileged()
			// The sync section appears only where it is enabled.
			pd.Nav["sync"] = rc.s.sync != nil && rc.roles.Has(PermSyncRead)
			// So does the File servers section.
			pd.Nav["files"] = rc.s.files != nil && rc.roles.Has(PermFilesRead)
		}
	}
	if pd.CSRF == "" {
		if c, err := rc.r.Cookie(preCookie); err == nil {
			pd.CSRF = c.Value
		}
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", pd); err != nil {
		rc.s.log.Error("template execution failed", "page", page, "err", err)
		http.Error(rc.w, "internal error", http.StatusInternalServerError)
		return
	}
	rc.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rc.w.WriteHeader(status)
	_, _ = rc.w.Write(buf.Bytes())
}

// errorPage shows a translated error with no internal detail.
func (rc *reqCtx) errorPage(status int, key string) {
	rc.render(status, "error", map[string]any{"Status": status, "Message": rc.T(key)})
}

func (s *Server) notFound(rc *reqCtx) { rc.errorPage(http.StatusNotFound, "err.not_found") }

// staticHandler serves the embedded CSS and images.
func (s *Server) staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(sub)
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.securityHeaders(w.Header())
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	}))
}
