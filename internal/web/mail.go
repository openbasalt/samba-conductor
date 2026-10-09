package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// E-mail: the queue (nil while [mail] is off), the templates with the
// organization's branding, and Settings > E-mail.

// Bounds of Settings > E-mail.
const (
	// mailTestsPerHour bounds the test messages of one administrator.
	mailTestsPerHour = 5
	// mailTestLifetime is how long a test message may wait for the relay.
	mailTestLifetime = time.Hour
	// mailLogRows is how many log rows the page shows.
	mailLogRows = 20
)

// MailEnabled reports whether messages can be sent ([mail] is configured
// and the queue runs).
func (s *Server) MailEnabled() bool { return s.mailq != nil }

// publicBase is the https base URL of the links and images in messages:
// the first WebAuthn origin (the host users open), or "" when none is
// configured.
func (s *Server) publicBase() string {
	if o := s.cfg.WebAuthnOrigins(); len(o) > 0 {
		return strings.TrimRight(o[0], "/")
	}
	return ""
}

// mailBrand is the branding part of a message's data in lang: the
// organization name, the light logo as an absolute URL (only with a
// public base URL), the primary color and the support contact.
func (s *Server) mailBrand(lang string) mail.Data {
	st := s.brand.Load()
	var doc branding.Branding
	if st != nil {
		doc = st.doc
	}
	d := mail.Data{OrgName: doc.OrgName, Primary: doc.PrimaryColor,
		Support: mail.Support{Email: doc.Support.Email, Phone: doc.Support.Phone, URL: doc.Support.URL, Text: doc.Text(lang).Help}}
	if a, ok := doc.Assets[branding.SlotLogoLight]; ok {
		if base := s.publicBase(); base != "" {
			d.Logo = base + assetURL(a)
		}
	}
	return d
}

// queueMail renders template name in lang with d (its branding fields are
// filled here) and queues it for to. expiresAt is when the message stops
// being worth sending (the expiry of the link it carries, or
// mail.NotificationLifetime from now for a notification); reference goes
// to the log (a token id, never personal data). The returned id names the
// message in the log.
func (s *Server) queueMail(ctx context.Context, name, lang, to string, d mail.Data, expiresAt time.Time, reference string) (string, error) {
	if s.mailq == nil {
		return "", errMailOff
	}
	b := s.mailBrand(lang)
	d.OrgName, d.Logo, d.Primary, d.Support = b.OrgName, b.Logo, b.Primary, b.Support
	subject, text, html, err := s.mailr.Render(name, lang, d)
	if err != nil {
		return "", err
	}
	return s.mailq.Enqueue(ctx, mail.Message{Kind: name, To: to, Subject: subject, Text: text, HTML: html}, expiresAt, reference)
}

// errMailOff: [mail] is not configured.
var errMailOff = errors.New("web: e-mail is not configured ([mail] host)")

// mailDir is the directory of message template overrides inside
// branding.templates_dir.
const mailDir = "mail"

// MailTemplatesDir is where message template overrides live: the mail
// directory of branding.templates_dir ("" when that is unset).
func MailTemplatesDir(templatesDir string) string {
	if templatesDir == "" {
		return ""
	}
	return filepath.Join(templatesDir, mailDir)
}

// loadMailTemplates loads the message templates and the overrides,
// logging what was decided (only when mail is on: otherwise nothing is
// ever sent with them).
func (s *Server) loadMailTemplates() error {
	r, err := mail.NewRenderer(s.cat, MailTemplatesDir(s.cfg.Branding.TemplatesDir))
	if err != nil {
		return err
	}
	s.mailr = r
	if s.mailq == nil {
		return nil
	}
	for _, f := range r.Findings {
		if f.Level == branding.LevelOK {
			s.log.Info("mail template", "file", f.File, "result", f.Message)
		} else {
			s.log.Warn("mail template", "file", f.File, "level", f.Level, "result", f.Message)
		}
	}
	return nil
}

// mailLogView is one row of the log on the page.
type mailLogView struct {
	store.MailLogRow
	KindKey string
}

// adminMail reads the signed-in administrator's own mail attribute (the
// default recipient of a test message); empty when it cannot be read.
func (s *Server) adminMail(ctx context.Context, rc *reqCtx) string {
	var addr string
	_ = rc.withConn(ctx, func(conn *ad.Conn) error {
		u, err := s.me(ctx, rc, conn)
		if err == nil {
			addr = u.Mail
		}
		return err
	})
	return addr
}

func (s *Server) handleMailSettings(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	s.mailSettingsPage(ctx, rc, http.StatusOK, "", "")
}

// mailSettingsPage renders Settings > E-mail; to is the test form's value
// (empty: the administrator's own address) and errKey an error message.
func (s *Server) mailSettingsPage(ctx context.Context, rc *reqCtx, status int, to, errKey string) {
	m := s.cfg.Mail
	d := map[string]any{"Enabled": s.mailq != nil, "M": m, "Relay": "", "PasswordFrom": "", "Max": mailTestsPerHour}
	if m.Enabled() {
		d["Relay"] = net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
		switch {
		case m.Username == "":
		case m.PasswordFile != "":
			d["PasswordFrom"] = "file"
		default:
			d["PasswordFrom"] = "credential"
		}
	}
	if s.mailr != nil {
		d["Overrides"] = s.mailr.Overridden
	}
	stats, err := s.store.MailStats(ctx, s.now().Add(-24*time.Hour))
	if err != nil {
		s.log.Error("mail stats", "err", err)
	}
	d["Stats"] = stats
	rows, err := s.store.MailLog(ctx, mailLogRows)
	if err != nil {
		s.log.Error("mail log", "err", err)
	}
	var views []mailLogView
	for _, r := range rows {
		v := mailLogView{MailLogRow: r}
		if key := "settings.mail.kind." + r.Kind; s.cat.Has(key) {
			v.KindKey = key
		}
		views = append(views, v)
	}
	d["Log"] = views
	if s.mailq != nil {
		if to == "" {
			to = s.adminMail(ctx, rc)
		}
		d["To"] = to
	}
	if errKey != "" {
		d["Error"] = rc.T(errKey)
	}
	rc.render(status, "mail_settings", d)
}

// handleMailTest queues the test message for the typed address (or the
// administrator's own), at most mailTestsPerHour per administrator.
func (s *Server) handleMailTest(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	to := rc.form("to")
	if s.mailq == nil {
		rc.errorPage(http.StatusConflict, "settings.mail.off.title")
		return
	}
	if _, err := mail.ParseRecipient(to); err != nil {
		s.mailSettingsPage(ctx, rc, http.StatusBadRequest, to, "settings.mail.test.invalid")
		return
	}
	domain := mail.Domain(to)
	rc.sess.mu.Lock()
	who := rc.sess.userSID.String()
	rc.sess.mu.Unlock()
	if !s.mailTestLimit.Allow(who) {
		s.audit(ctx, rc, "mail.test", domain, "test message refused: more than 5 per hour", store.ResultDenied)
		s.mailSettingsPage(ctx, rc, http.StatusTooManyRequests, to, "settings.mail.test.limited")
		return
	}
	id, err := s.queueMail(ctx, mail.TemplateTest, rc.lang, to, mail.Data{When: s.now()}, s.now().Add(mailTestLifetime), "settings-test")
	if err != nil {
		s.log.Error("mail test", "err", err)
		s.audit(ctx, rc, "mail.test", domain, "test message could not be queued", store.ResultFailed)
		s.mailSettingsPage(ctx, rc, http.StatusInternalServerError, to, "settings.mail.test.failed")
		return
	}
	s.audit(ctx, rc, "mail.test", domain, "test message queued, id "+id, store.ResultOK)
	rc.flashOK("settings.mail.test.queued", to)
	rc.redirect("/admin/settings/mail")
}
