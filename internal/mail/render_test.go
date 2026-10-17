package mail

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor/internal/i18n"
)

// untranslated matches a catalog key printed instead of its message.
var untranslated = regexp.MustCompile(`\bmail\.(subject|duration|button|link_hint|footer)`)

func fullData() Data {
	return Data{OrgName: "Example <Org>", Logo: "https://conductor.example.com/branding/assets/abc", Primary: "#1d4ed8",
		Support: Support{Email: "help@example.com", Phone: "+1 555 0100", URL: "https://help.example.com", Text: "Call us."},
		Link:    "https://conductor.example.com/link/tok?x=1&y=2", Username: "ana.souza",
		Expires: time.Date(2026, 3, 4, 5, 6, 0, 0, time.UTC), ValidFor: 72 * time.Hour,
		When: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC), From: "192.0.2.10", Code: "482913"}
}

func TestRenderEveryTemplate(t *testing.T) {
	cat := i18n.MustLoad()
	r, err := NewRenderer(cat, "")
	if err != nil {
		t.Fatal(err)
	}
	// What each template must show (in both forms).
	want := map[string][]string{
		TemplateTest:             {"2026"},
		TemplateInvitation:       {"ana.souza", "conductor.example.com/link/tok", "72"},
		TemplateReset:            {"ana.souza", "conductor.example.com/link/tok"},
		TemplatePasswordChanged:  {"ana.souza", "192.0.2.10"},
		TemplateAlternateVerify:  {"482913"},
		TemplateAlternateChanged: {"2026"},
	}
	for _, name := range Templates {
		for _, lang := range i18n.Languages {
			subject, text, html, err := r.Render(name, lang, fullData())
			if err != nil {
				t.Fatalf("%s %s: %v", name, lang, err)
			}
			if subject == "" || strings.Contains(subject, "{0}") || strings.ContainsAny(subject, "\r\n") || !strings.Contains(subject, "Example <Org>") {
				t.Errorf("%s %s: subject %q", name, lang, subject)
			}
			for _, w := range want[name] {
				if !strings.Contains(text, w) || !strings.Contains(html, w) {
					t.Errorf("%s %s: lacks %q", name, lang, w)
				}
			}
			for _, bad := range []string{"<no value>", "ZgotmplZ", "{0}", "<script"} {
				if strings.Contains(text, bad) || strings.Contains(html, bad) {
					t.Errorf("%s %s: contains %q", name, lang, bad)
				}
			}
			if untranslated.MatchString(text) || untranslated.MatchString(html) {
				t.Errorf("%s %s: untranslated catalog key", name, lang)
			}
			// HTML is escaped, text is not.
			if strings.Contains(html, "Example <Org>") || !strings.Contains(html, "Example &lt;Org&gt;") {
				t.Errorf("%s %s: organization name not escaped in HTML", name, lang)
			}
			if !strings.Contains(text, "Example <Org>") {
				t.Errorf("%s %s: text lacks the organization name", name, lang)
			}
			if !strings.Contains(html, `lang="`+lang+`"`) || !strings.Contains(html, "#1d4ed8") ||
				!strings.Contains(html, "https://conductor.example.com/branding/assets/abc") {
				t.Errorf("%s %s: language, color or logo missing", name, lang)
			}
			// No remote resource other than the logo.
			if n := strings.Count(html, "<img"); n != 1 || strings.Contains(html, "<link") || strings.Contains(html, "url(") {
				t.Errorf("%s %s: remote resources (%d images)", name, lang, n)
			}
			if !strings.Contains(text, "help@example.com") || !strings.Contains(html, "mailto:help@example.com") {
				t.Errorf("%s %s: support contact missing", name, lang)
			}
		}
	}
	// pt-BR and en differ.
	_, en, _, _ := r.Render(TemplateInvitation, "en", fullData())
	_, pt, _, _ := r.Render(TemplateInvitation, "pt-BR", fullData())
	if en == pt || !strings.Contains(pt, "04/03/2026 05:06 UTC") || !strings.Contains(en, "2026-03-04 05:06 UTC") {
		t.Fatalf("languages:\n%s\n%s", en, pt)
	}
	// An unknown language falls back to English; an unknown template fails.
	if _, x, _, err := r.Render(TemplateInvitation, "fr", fullData()); err != nil || x != en {
		t.Fatalf("fallback: %v", err)
	}
	if _, _, _, err := r.Render("nope", "en", fullData()); err == nil {
		t.Fatal("unknown template rendered")
	}
}

func TestRenderSanitizesBranding(t *testing.T) {
	r, err := NewRenderer(i18n.MustLoad(), "")
	if err != nil {
		t.Fatal(err)
	}
	d := Data{OrgName: "Org\r\nBcc: x@example.net", Logo: "http://insecure.example.com/logo.png", Primary: "red;background:url(x)",
		When: time.Now(), ByAdministrator: true, From: "192.0.2.99", Username: "u"}
	subject, text, html, err := r.Render(TemplatePasswordChanged, "en", d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatalf("subject %q", subject)
	}
	if strings.Contains(html, "insecure.example.com") || strings.Contains(html, "<img") {
		t.Fatal("non-https logo used")
	}
	if strings.Contains(html, "red;") || !strings.Contains(html, ProductPrimary) {
		t.Fatal("invalid color used")
	}
	// A change by an administrator does not show the client address.
	if strings.Contains(text, "192.0.2.99") || strings.Contains(html, "192.0.2.99") {
		t.Fatal("address shown for an administrator's change")
	}
	// Defaults: product name.
	subject, _, _, _ = r.Render(TemplateTest, "en", Data{When: time.Now()})
	if !strings.Contains(subject, ProductName) {
		t.Fatalf("default name: %q", subject)
	}
}

func TestDurations(t *testing.T) {
	r, _ := NewRenderer(i18n.MustLoad(), "")
	for d, want := range map[time.Duration]string{72 * time.Hour: "72 hours", time.Hour: "1 hour", 15 * time.Minute: "15 minutes",
		time.Minute: "1 minute", 90 * time.Second: "2 minutes", 0: ""} {
		if got := r.formatDuration("en", d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
	if got := r.formatDuration("pt-BR", 72*time.Hour); got != "72 horas" {
		t.Errorf("pt-BR: %q", got)
	}
}

func writeOverride(t *testing.T, dir, file, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findingFor(fs []branding.Finding, file string) (branding.Finding, bool) {
	for _, f := range fs {
		if f.File == file {
			return f, true
		}
	}
	return branding.Finding{}, false
}

func TestOverrides(t *testing.T) {
	cat := i18n.MustLoad()
	dir := t.TempDir()
	writeOverride(t, dir, "test.en.txt", "Custom test from {{.OrgName}} at {{.When}}\n{{template \"text-bottom\" .}}")
	writeOverride(t, dir, "test.en.html", "{{template \"mail-top\" .}}<p>Custom {{.OrgName}}</p>{{template \"mail-bottom\" .}}")
	// Unknown placeholder in a branch the sample data does not reach.
	writeOverride(t, dir, "reset.en.txt", "{{if .ByAdministrator}}{{.Password}}{{end}}{{.Link}}")
	writeOverride(t, dir, "reset.en.html", "<p>{{.Link}}</p><script>alert(1)</script>")
	writeOverride(t, dir, "invitation.en.html", `<a href="{{.Link}}" onclick="x()">go</a>`)
	writeOverride(t, dir, "invitation.pt-BR.txt", "{{.Link")
	writeOverride(t, dir, "password_changed.en.txt", `{{template "nope" .}}`)
	writeOverride(t, dir, "alternate_verify.en.txt", "{{with .Support}}{{.Secret}}{{end}}")
	writeOverride(t, dir, "notes.txt", "hello")

	findings, err := CheckOverrides(cat, dir)
	if err != nil {
		t.Fatal(err)
	}
	for file, level := range map[string]string{
		"mail/test.en.txt": branding.LevelOK, "mail/test.en.html": branding.LevelOK,
		"mail/reset.en.txt": branding.LevelError, "mail/reset.en.html": branding.LevelError,
		"mail/invitation.en.html": branding.LevelError, "mail/invitation.pt-BR.txt": branding.LevelError,
		"mail/password_changed.en.txt": branding.LevelError, "mail/alternate_verify.en.txt": branding.LevelError,
		"mail/notes.txt": branding.LevelWarning,
	} {
		f, ok := findingFor(findings, file)
		if !ok || f.Level != level {
			t.Errorf("%s: %+v (found %v), want %s", file, f, ok, level)
		}
	}
	if f, _ := findingFor(findings, "mail/reset.en.txt"); !strings.Contains(f.Message, "Password") {
		t.Errorf("unknown placeholder not named: %q", f.Message)
	}

	r, err := NewRenderer(cat, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Overridden) != 2 {
		t.Fatalf("overridden %v", r.Overridden)
	}
	_, text, html, err := r.Render(TemplateTest, "en", Data{OrgName: "Acme", When: time.Now()})
	if err != nil || !strings.HasPrefix(text, "Custom test from Acme") || !strings.Contains(html, "<p>Custom Acme</p>") {
		t.Fatalf("override not used: %v\n%s\n%s", err, text, html)
	}
	// Refused overrides leave the built-in template in use.
	_, text, html, err = r.Render(TemplateReset, "en", fullData())
	if err != nil || strings.Contains(html, "<script") || !strings.Contains(text, "ana.souza") {
		t.Fatalf("built-in reset not used: %v", err)
	}
	// Other languages keep the built-in templates.
	if _, text, _, _ := r.Render(TemplateTest, "pt-BR", Data{When: time.Now()}); strings.Contains(text, "Custom") {
		t.Fatal("override leaked to pt-BR")
	}

	if fs, err := CheckOverrides(cat, filepath.Join(dir, "missing")); err != nil || fs != nil {
		t.Fatalf("missing dir: %v %v", fs, err)
	}
	if src, ok := BuiltinSource("reset.pt-BR.html"); !ok || !strings.Contains(src, "mail-top") {
		t.Fatal("BuiltinSource")
	}
	if _, ok := BuiltinSource("../render.go"); ok {
		t.Fatal("BuiltinSource outside the templates")
	}
	if len(Placeholders()) == 0 {
		t.Fatal("Placeholders")
	}
}
