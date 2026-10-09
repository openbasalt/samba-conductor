package mail

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	texttemplate "text/template"
	"text/template/parse"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor/internal/i18n"
)

// Template names.
const (
	TemplateTest             = "test"
	TemplateInvitation       = "invitation"
	TemplateReset            = "reset"
	TemplatePasswordChanged  = "password_changed"
	TemplateAlternateVerify  = "alternate_verify"
	TemplateAlternateChanged = "alternate_changed"
)

// Templates lists every template; each exists as <name>.<lang>.txt and
// <name>.<lang>.html for every language, and its subject is the message
// mail.subject.<name> of the i18n catalog.
var Templates = []string{TemplateTest, TemplateInvitation, TemplateReset, TemplatePasswordChanged,
	TemplateAlternateVerify, TemplateAlternateChanged}

// Product look when the branding sets nothing.
const (
	ProductName    = "Samba Conductor"
	ProductPrimary = "#0f766e"
)

//go:embed templates/*.txt templates/*.html
var builtinFS embed.FS

// Support is the organization's support contact (Settings > Branding).
type Support struct {
	Email string
	Phone string
	URL   string
	// Text is the help text of the branding in the message's language.
	Text string
}

// Any reports whether a contact is set.
func (s Support) Any() bool { return s.Email != "" || s.Phone != "" || s.URL != "" }

// Data is what a caller knows about a message. Times are formatted in the
// message's language by Render.
type Data struct {
	// Branding: organization name (empty: the product name), logo
	// (absolute https URL, or empty), primary color (#rrggbb, empty: the
	// product color) and support contact.
	OrgName string
	Logo    string
	Primary string
	Support Support

	// Link is the one-time link (invitation, reset).
	Link string
	// Username is the logon name (sAMAccountName) the user signs in with.
	Username string
	// Expires is when the link or code stops working; ValidFor how long
	// it is valid from now ("72 hours").
	Expires  time.Time
	ValidFor time.Duration
	// When a change happened (password changed, address changed).
	When time.Time
	// From is the client address a change came from; ByAdministrator
	// says an administrator made it instead (From is then not shown).
	From            string
	ByAdministrator bool
	// Code is a verification code (alternate address).
	Code string
}

// View is what the templates see.
type View struct {
	Lang    string
	Subject string
	OrgName string
	Logo    string
	Primary string
	Support Support

	Link            string
	Username        string
	ExpiresAt       string
	ExpiresIn       string
	When            string
	From            string
	ByAdministrator bool
	Code            string
}

var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// sampleView is the data overrides are checked with.
func sampleView(lang string) View {
	return View{Lang: lang, Subject: "Sample subject", OrgName: "Example Org", Logo: "https://conductor.example.com/branding/assets/sample",
		Primary: ProductPrimary, Support: Support{Email: "help@example.com", Phone: "+1 555 0100", URL: "https://help.example.com", Text: "Help text"},
		Link: "https://conductor.example.com/link/sample", Username: "sample.user", ExpiresAt: "2026-01-02 03:04 UTC", ExpiresIn: "72 hours",
		When: "2026-01-02 03:04 UTC", From: "192.0.2.10", Code: "123456"}
}

// sparseView is the sample with every optional part empty and the other
// branch of the flags, so both sides of a conditional are executed.
func sparseView(lang string) View {
	return View{Lang: lang, Subject: "Sample subject", OrgName: "Example Org", Primary: ProductPrimary, ByAdministrator: true}
}

// Renderer renders the messages: built-in templates, replaced one by one
// by valid overrides read at startup.
type Renderer struct {
	cat  *i18n.Catalog
	text map[string]*texttemplate.Template // "<name>.<lang>"
	html map[string]*htmltemplate.Template
	// Overridden lists the override files in use; Findings what loading
	// the override directory decided.
	Overridden []string
	Findings   []branding.Finding
}

// files of a template in one language.
func files(name, lang string) (txt, html string) {
	return name + "." + lang + ".txt", name + "." + lang + ".html"
}

// NewRenderer loads the built-in templates and the overrides in dir
// (<branding.templates_dir>/mail; empty: none). A refused override is
// reported in Findings and the built-in template stays in use; a broken
// built-in template is an error (a build defect).
func NewRenderer(cat *i18n.Catalog, dir string) (*Renderer, error) {
	r := &Renderer{cat: cat, text: map[string]*texttemplate.Template{}, html: map[string]*htmltemplate.Template{}}
	for _, name := range Templates {
		for _, lang := range i18n.Languages {
			tf, hf := files(name, lang)
			for _, f := range []string{tf, hf} {
				src, err := builtinFS.ReadFile("templates/" + f)
				if err != nil {
					return nil, fmt.Errorf("mail: built-in template %s: %w", f, err)
				}
				if err := r.install(f, string(src)); err != nil {
					return nil, fmt.Errorf("mail: built-in template %s: %w", f, err)
				}
			}
		}
	}
	if dir == "" {
		return r, nil
	}
	for _, f := range overrideFiles(dir, &r.Findings) {
		src, err := os.ReadFile(filepath.Join(dir, f))
		if err == nil {
			err = r.install(f, string(src))
		}
		if err != nil {
			r.Findings = append(r.Findings, branding.Finding{File: "mail/" + f, Level: branding.LevelError,
				Message: err.Error() + "; the built-in template is used"})
			continue
		}
		r.Overridden = append(r.Overridden, f)
		r.Findings = append(r.Findings, branding.Finding{File: "mail/" + f, Level: branding.LevelOK, Message: "override in use"})
	}
	return r, nil
}

// CheckOverrides checks <dir> (`conductor templates check`): every file is
// parsed, executed with sample data (unknown placeholders fail) and linted.
func CheckOverrides(cat *i18n.Catalog, dir string) ([]branding.Finding, error) {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	r, err := NewRenderer(cat, dir)
	if err != nil {
		return nil, err
	}
	return r.Findings, nil
}

// known reports whether f is the file of a template.
func known(f string) bool {
	for _, name := range Templates {
		for _, lang := range i18n.Languages {
			tf, hf := files(name, lang)
			if f == tf || f == hf {
				return true
			}
		}
	}
	return false
}

// overrideFiles lists the template files of dir; unknown files are
// reported and ignored.
func overrideFiles(dir string, findings *[]branding.Finding) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			*findings = append(*findings, branding.Finding{File: "mail/", Level: branding.LevelError, Message: err.Error()})
		}
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		switch {
		case e.IsDir() || strings.HasPrefix(n, "."):
		case !e.Type().IsRegular():
			*findings = append(*findings, branding.Finding{File: "mail/" + n, Level: branding.LevelError, Message: "not a regular file; ignored"})
		case !known(n):
			*findings = append(*findings, branding.Finding{File: "mail/" + n, Level: branding.LevelWarning,
				Message: "unknown file; expected <name>.<lang>.txt or .html with name one of " + strings.Join(Templates, ", ")})
		default:
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// maxTemplate bounds a template file.
const maxTemplate = 64 << 10

var scriptRE = regexp.MustCompile(`(?i)<\s*script|javascript:|\son[a-z]+\s*=`)

// install parses one template file (built-in or override), checks that
// it names only known placeholders and templates, executes it with sample
// data (every field set, then the sparse case) and makes it current.
func (r *Renderer) install(file, src string) error {
	if len(src) > maxTemplate {
		return fmt.Errorf("larger than %d KiB", maxTemplate>>10)
	}
	parts := strings.Split(file, ".")
	if len(parts) != 3 {
		return errors.New("bad file name")
	}
	key, lang, ext := parts[0]+"."+parts[1], parts[1], parts[2]
	views := []View{sampleView(lang), sparseView(lang)}
	var buf bytes.Buffer
	switch ext {
	case "txt":
		t, err := texttemplate.New(file).Funcs(r.textFuncs(lang)).Option("missingkey=error").Parse(textPartials)
		if err == nil {
			_, err = t.Parse(src)
		}
		if err != nil {
			return err
		}
		for _, tt := range t.Templates() {
			if err := checkTree(tt.Tree, func(n string) bool { return t.Lookup(n) != nil }); err != nil {
				return err
			}
		}
		for _, v := range views {
			buf.Reset()
			if err := t.ExecuteTemplate(&buf, file, v); err != nil {
				return err
			}
		}
		r.text[key] = t
	case "html":
		if scriptRE.MatchString(src) {
			return errors.New("scripts, javascript: URLs and event handlers are not allowed")
		}
		t, err := htmltemplate.New(file).Funcs(r.htmlFuncs(lang)).Option("missingkey=error").Parse(htmlPartials)
		if err == nil {
			_, err = t.Parse(src)
		}
		if err != nil {
			return err
		}
		// Checked before the first execution: escaping rewrites the trees.
		for _, tt := range t.Templates() {
			if err := checkTree(tt.Tree, func(n string) bool { return t.Lookup(n) != nil }); err != nil {
				return err
			}
		}
		for _, v := range views {
			buf.Reset()
			if err := t.ExecuteTemplate(&buf, file, v); err != nil {
				return err
			}
			if strings.Contains(buf.String(), "ZgotmplZ") {
				return errors.New("a placeholder is used where html/template refuses it (ZgotmplZ)")
			}
		}
		r.html[key] = t
	default:
		return errors.New("bad file name")
	}
	return nil
}

// placeholders are the field names a template may use: the fields of View
// and of Support, and the methods of Support.
var placeholders = func() map[string]bool {
	m := map[string]bool{}
	for _, typ := range []reflect.Type{reflect.TypeFor[View](), reflect.TypeFor[Support]()} {
		for i := range typ.NumField() {
			m[typ.Field(i).Name] = true
		}
		for i := range typ.NumMethod() {
			m[typ.Method(i).Name] = true
		}
	}
	return m
}()

// Placeholders lists the field names templates may use (`conductor
// templates list`).
func Placeholders() []string {
	out := make([]string, 0, len(placeholders))
	for k := range placeholders {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// checkTree refuses a field name that is not a placeholder and a template
// call to a name the set does not define, in every branch (execution with
// sample data only reaches the branches the data selects).
func checkTree(tree *parse.Tree, defined func(string) bool) error {
	if tree == nil {
		return nil
	}
	var walk func(n parse.Node) error
	fields := func(idents []string) error {
		for _, id := range idents {
			if !placeholders[id] {
				return fmt.Errorf("unknown placeholder .%s (known: %s)", id, strings.Join(Placeholders(), ", "))
			}
		}
		return nil
	}
	walk = func(n parse.Node) error {
		switch n := n.(type) {
		case nil:
			return nil
		case *parse.ListNode:
			if n == nil {
				return nil
			}
			for _, c := range n.Nodes {
				if err := walk(c); err != nil {
					return err
				}
			}
		case *parse.ActionNode:
			return walk(n.Pipe)
		case *parse.PipeNode:
			if n == nil {
				return nil
			}
			for _, c := range n.Cmds {
				if err := walk(c); err != nil {
					return err
				}
			}
		case *parse.CommandNode:
			for _, a := range n.Args {
				if err := walk(a); err != nil {
					return err
				}
			}
		case *parse.FieldNode:
			return fields(n.Ident)
		case *parse.ChainNode:
			if err := walk(n.Node); err != nil {
				return err
			}
			return fields(n.Field)
		case *parse.VariableNode:
			return fields(n.Ident[1:])
		case *parse.IfNode:
			return walkBranch(walk, &n.BranchNode)
		case *parse.RangeNode:
			return walkBranch(walk, &n.BranchNode)
		case *parse.WithNode:
			return walkBranch(walk, &n.BranchNode)
		case *parse.TemplateNode:
			if !defined(n.Name) {
				return fmt.Errorf("unknown template %q", n.Name)
			}
			return walk(n.Pipe)
		}
		return nil
	}
	return walk(tree.Root)
}

func walkBranch(walk func(parse.Node) error, b *parse.BranchNode) error {
	for _, n := range []parse.Node{b.Pipe, b.List, b.ElseList} {
		if n == nil || reflect.ValueOf(n).IsNil() {
			continue
		}
		if err := walk(n); err != nil {
			return err
		}
	}
	return nil
}

func (r *Renderer) t(lang string) func(key string, args ...any) string {
	return func(key string, args ...any) string { return r.cat.T(lang, key, args...) }
}

func (r *Renderer) textFuncs(lang string) texttemplate.FuncMap {
	return texttemplate.FuncMap{"t": r.t(lang)}
}

func (r *Renderer) htmlFuncs(lang string) htmltemplate.FuncMap {
	return htmltemplate.FuncMap{"t": r.t(lang)}
}

// FormatTime formats a time for a message in lang (UTC, numeric date).
func FormatTime(lang string, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	if lang == "pt-BR" {
		return t.UTC().Format("02/01/2006 15:04") + " UTC"
	}
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

// formatDuration says how long something is valid ("72 hours").
func (r *Renderer) formatDuration(lang string, d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d%time.Hour == 0 && d >= time.Hour:
		if h := int(d / time.Hour); h != 1 {
			return r.cat.T(lang, "mail.duration.hours", h)
		}
		return r.cat.T(lang, "mail.duration.hour")
	default:
		m := int((d + time.Minute - 1) / time.Minute)
		if m == 1 {
			return r.cat.T(lang, "mail.duration.minute")
		}
		return r.cat.T(lang, "mail.duration.minutes", m)
	}
}

// Render renders the subject and both bodies of a template in lang (an
// unknown language falls back to English).
func (r *Renderer) Render(name, lang string, d Data) (subject, text, html string, err error) {
	if !slices.Contains(Templates, name) {
		return "", "", "", fmt.Errorf("mail: unknown template %q", name)
	}
	if !i18n.Valid(lang) {
		lang = i18n.Languages[0]
	}
	v := View{Lang: lang, OrgName: d.OrgName, Logo: d.Logo, Primary: d.Primary, Support: d.Support, Link: d.Link, Username: d.Username,
		ExpiresAt: FormatTime(lang, d.Expires), ExpiresIn: r.formatDuration(lang, d.ValidFor), When: FormatTime(lang, d.When),
		From: d.From, ByAdministrator: d.ByAdministrator, Code: d.Code}
	if v.OrgName == "" {
		v.OrgName = ProductName
	}
	if !colorRE.MatchString(v.Primary) {
		v.Primary = ProductPrimary
	}
	if !strings.HasPrefix(v.Logo, "https://") {
		v.Logo = ""
	}
	v.Subject = headerValue(r.cat.T(lang, "mail.subject."+name, v.OrgName))
	key := name + "." + lang
	var tb, hb bytes.Buffer
	tf, hf := files(name, lang)
	if err := r.text[key].ExecuteTemplate(&tb, tf, v); err != nil {
		return "", "", "", fmt.Errorf("mail: %s: %w", tf, err)
	}
	if err := r.html[key].ExecuteTemplate(&hb, hf, v); err != nil {
		return "", "", "", fmt.Errorf("mail: %s: %w", hf, err)
	}
	return v.Subject, tb.String(), hb.String(), nil
}

// BuiltinSource returns a built-in template file (`conductor templates
// show mail/<file>`).
func BuiltinSource(file string) (string, bool) {
	if !known(file) {
		return "", false
	}
	b, err := builtinFS.ReadFile("templates/" + file)
	return string(b), err == nil
}

// Partials available to every template.
var (
	textPartials = mustRead("templates/layout.txt")
	htmlPartials = mustRead("templates/layout.html")
)

func mustRead(name string) string {
	b, err := builtinFS.ReadFile(name)
	if err != nil {
		panic("mail: missing " + name)
	}
	return string(b)
}
