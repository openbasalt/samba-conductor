package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

const mailTestPassword = "relay-password-never-shown"

// mailHarness is a harness with [mail] configured and a queue without a
// sender (messages stay queued).
func mailHarness(t *testing.T) *harness {
	t.Helper()
	pw := filepath.Join(t.TempDir(), "smtp-password")
	if err := os.WriteFile(pw, []byte(mailTestPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *config.Config) {
		c.Mail = config.Mail{Host: "smtp.example.com", Port: 587, Security: config.MailSTARTTLS, Username: "relay-user", PasswordFile: pw,
			From: "Example Org <no-reply@example.com>", MaxPerHour: 120}
	})
	box, err := secret.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	h.s.mailq = mail.NewQueue(h.st, box, nil, mail.QueueOptions{MaxPerHour: 120, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return h.now }})
	return h
}

// interactive matches the form controls of a page.
var interactive = regexp.MustCompile(`<(input|button|select|textarea)\b[^>]*>`)

// mustTagE2E fails when a visible form control of body has no data-e2e.
func mustTagE2E(t *testing.T, body string) {
	t.Helper()
	for _, tag := range interactive.FindAllString(body, -1) {
		if strings.Contains(tag, `type="hidden"`) {
			continue
		}
		if !strings.Contains(tag, "data-e2e=") {
			t.Errorf("form control without data-e2e: %s", tag)
		}
	}
}

func TestMailSettingsPage(t *testing.T) {
	h := mailHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("GET", "/admin/settings/mail", admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	page := w.Body.String()
	mustContainAll(t, "mail settings", page, `data-e2e="nav-link-mail"`, `data-e2e="mail-text-relay"`, "smtp.example.com:587",
		`data-e2e="mail-input-to"`, `data-e2e="mail-btn-test"`, `data-e2e="mail-text-pending"`, `data-e2e="mail-text-no-log"`, "relay-user")
	if strings.Contains(page, mailTestPassword) || strings.Contains(page, h.s.cfg.Mail.PasswordFile) {
		t.Fatal("the page shows the password or its file")
	}
	mustTagE2E(t, page)

	// Not for helpdesk, auditors or users.
	for _, who := range []struct {
		sam string
		mfa bool
	}{{"helpdesk.user", true}, {"auditor.user", true}, {"normal.user", false}} {
		tok := h.session(t, who.sam, stageFull, who.mfa)
		if w := h.do("GET", "/admin/settings/mail", tok, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: GET %d", who.sam, w.Code)
		}
		if w := h.do("POST", "/admin/settings/mail/test", tok, url.Values{"to": {"x@example.org"}}); w.Code != http.StatusForbidden {
			t.Errorf("%s: POST %d", who.sam, w.Code)
		}
	}
	if st, _ := h.st.MailStats(context.Background(), h.now.Add(-time.Hour)); st.Pending != 0 {
		t.Fatal("a refused request queued a message")
	}
}

func TestMailTestMessage(t *testing.T) {
	h := mailHarness(t)
	ctx := context.Background()
	admin := h.session(t, "lab.admin", stageFull, true)

	// Invalid or injected addresses are refused and queue nothing.
	for _, to := range []string{"", "nobody", "a@example.org\r\nBcc: b@example.net", "a@example.org, b@example.net"} {
		w := h.do("POST", "/admin/settings/mail/test", admin, url.Values{"to": {to}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `data-e2e="form-text-error"`) {
			t.Errorf("%q: status %d", to, w.Code)
		}
	}
	// Without the CSRF token nothing happens.
	if w := h.do("POST", "/admin/settings/mail/test", admin, url.Values{"to": {"a@example.org"}, "csrf": {"wrong"}}); w.Code == http.StatusSeeOther {
		t.Fatal("POST without CSRF accepted")
	}

	for i := range mailTestsPerHour {
		w := h.do("POST", "/admin/settings/mail/test", admin, url.Values{"to": {"Ops <ops@Example.org>"}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("test %d: status %d %s", i+1, w.Code, w.Body.String())
		}
	}
	w := h.do("POST", "/admin/settings/mail/test", admin, url.Values{"to": {"ops@example.org"}})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d", w.Code)
	}
	st, err := h.st.MailStats(ctx, h.now.Add(-time.Hour))
	if err != nil || st.Pending != mailTestsPerHour {
		t.Fatalf("queued %+v %v", st, err)
	}
	rows, _ := h.st.MailLog(ctx, 10)
	if len(rows) != mailTestsPerHour || rows[0].Kind != mail.TemplateTest || rows[0].RecipientDomain != "example.org" {
		t.Fatalf("log %+v", rows)
	}

	// Audited mail.test, with the recipient's domain only.
	evs, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "mail.test"}, 0, 100)
	ok, denied := 0, 0
	for _, e := range evs {
		if strings.Contains(e.Target+e.Detail, "ops@") {
			t.Fatalf("audit keeps the address: %+v", e)
		}
		switch e.Result {
		case store.ResultOK:
			ok++
		case store.ResultDenied:
			denied++
		}
	}
	if ok != mailTestsPerHour || denied != 1 {
		t.Fatalf("audit ok=%d denied=%d", ok, denied)
	}

	// The limit is per administrator, not per session: a new session of
	// the same account is still over it.
	other := h.session(t, "lab.admin", stageFull, true)
	if w := h.do("POST", "/admin/settings/mail/test", other, url.Values{"to": {"ops@example.org"}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("same administrator, new session: %d", w.Code)
	}

	// The page lists the queued messages without their address.
	page := h.do("GET", "/admin/settings/mail", admin, nil).Body.String()
	if !strings.Contains(page, `data-e2e="mail-table-log"`) || strings.Contains(page, "ops@") {
		t.Fatal("log table")
	}
}

func TestMailOff(t *testing.T) {
	h := newHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	page := h.do("GET", "/admin/settings/mail", admin, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `data-e2e="mail-card-off"`) ||
		strings.Contains(page.Body.String(), `data-e2e="mail-btn-test"`) {
		t.Fatalf("off page %d", page.Code)
	}
	if w := h.do("POST", "/admin/settings/mail/test", admin, url.Values{"to": {"a@example.org"}}); w.Code != http.StatusConflict {
		t.Fatalf("POST while off: %d", w.Code)
	}
	if _, err := h.s.queueMail(context.Background(), mail.TemplateTest, "en", "a@example.org", mail.Data{}, h.now.Add(time.Hour), ""); err == nil {
		t.Fatal("queued while off")
	}
}

func TestMailBrandingInMessages(t *testing.T) {
	h := mailHarness(t)
	h.s.cfg.WebAuthn.Origins = []string{"https://conductor.example.com"}
	h.s.applyBranding(1, branding.Branding{OrgName: "Example Org", PrimaryColor: "#1d4ed8",
		Assets: map[string]branding.Asset{branding.SlotLogoLight: {SHA256: "abc123"}}}, nil)
	d := h.s.mailBrand("en")
	if d.OrgName != "Example Org" || d.Primary != "#1d4ed8" || d.Logo != "https://conductor.example.com/branding/assets/abc123" {
		t.Fatalf("%+v", d)
	}
}

func TestTemplatesCheckIncludesMail(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "mail"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mail", "test.en.html"), []byte("<p>{{.OrgName}}</p><script>x</script>"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Branding.TemplatesDir = dir
	fs, err := CheckTemplates(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var mailErr bool
	for _, f := range fs {
		if f.File == "mail" {
			t.Errorf("the mail directory reported as a partial: %+v", f)
		}
		if f.File == "mail/test.en.html" && f.Level == branding.LevelError {
			mailErr = true
		}
	}
	if !mailErr {
		t.Fatalf("mail override not checked: %+v", fs)
	}
}
