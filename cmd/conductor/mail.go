package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/i18n"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/web"
)

const mailUsage = "usage: conductor mail test --to ADDRESS [--password-file FILE] [--lang en|pt-BR] [--config FILE] | status [--config FILE]"

// newMailSender builds the SMTP sender of [mail]; passwordFile overrides
// where the relay password is read from (the command line test, run
// outside the service and its credentials).
func newMailSender(cfg *config.Config, passwordFile string) (*mail.SMTP, error) {
	path := passwordFile
	if path == "" && cfg.Mail.Username != "" {
		p, err := cfg.MailPasswordPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	pw, err := mail.LoadPassword(path)
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	return mail.NewSMTP(cfg.Mail, pw)
}

// cmdMail tests the relay and shows the queue.
func cmdMail(args []string) error {
	if len(args) < 1 {
		return errors.New(mailUsage)
	}
	switch args[0] {
	case "test":
		return cmdMailTest(args[1:])
	case "status":
		return cmdMailStatus(args[1:])
	}
	return errors.New(mailUsage)
}

// cmdMailTest sends the test message straight to the relay (not through
// the queue), so the relay's answer is printed here. It reads no state:
// the message has the product look and the template overrides.
func cmdMailTest(args []string) error {
	fs := flag.NewFlagSet("mail test", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	to := fs.String("to", "", "recipient address")
	pwFile := fs.String("password-file", "", "relay password file (default: mail.password_file, or the smtp-password credential)")
	lang := fs.String("lang", "", "message language, en or pt-BR (default: ui.default_language)")
	_ = fs.Parse(args)
	if *to == "" {
		return errors.New(mailUsage)
	}
	if _, err := mail.ParseRecipient(*to); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if !cfg.Mail.Enabled() {
		return errors.New("e-mail is off: set host in the [mail] section")
	}
	if *lang == "" {
		*lang = cfg.UI.DefaultLanguage
	}
	if !i18n.Valid(*lang) {
		return errors.New("--lang must be en or pt-BR")
	}
	if cfg.Mail.Username != "" && *pwFile == "" && cfg.Mail.PasswordFile == "" && os.Getenv("CREDENTIALS_DIRECTORY") == "" {
		// The smtp-password credential exists only inside the service.
		return errors.New("the relay password comes from the smtp-password credential of the service: pass --password-file with the file it is loaded from (as root)")
	}
	sender, err := newMailSender(cfg, *pwFile)
	if err != nil {
		return err
	}
	cat, err := i18n.Load()
	if err != nil {
		return err
	}
	r, err := mail.NewRenderer(cat, web.MailTemplatesDir(cfg.Branding.TemplatesDir))
	if err != nil {
		return err
	}
	for _, f := range r.Findings {
		fmt.Fprintln(os.Stderr, "templates: "+f.String())
	}
	subject, text, html, err := r.Render(mail.TemplateTest, *lang, mail.Data{When: time.Now()})
	if err != nil {
		return err
	}
	fmt.Printf("sending a test message to %s through %s\n", *to, sender.Describe())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := sender.Send(ctx, mail.Message{Kind: mail.TemplateTest, To: *to, Subject: subject, Text: text, HTML: html}); err != nil {
		return fmt.Errorf("the relay did not accept the message: %w", err)
	}
	fmt.Println("the relay accepted the message; delivery to the mailbox is up to the relay (check its log and the recipient's spam folder)")
	return nil
}

// cmdMailStatus prints the relay settings, the queue and the recent
// messages (as the database owner).
func cmdMailStatus(args []string) error {
	fs := flag.NewFlagSet("mail status", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	m := cfg.Mail
	if !m.Enabled() {
		fmt.Println("e-mail: off (no [mail] host)")
	} else {
		auth := "none"
		if m.Username != "" {
			auth = "user " + m.Username
		}
		fmt.Printf("e-mail: on\nrelay: %s:%d (%s)\nauthentication: %s\nfrom: %s\nceiling: %d per hour\n", m.Host, m.Port, m.Security, auth, m.From, m.MaxPerHour)
	}
	if err := checkDBOwner(cfg.State.Database); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.State.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	stats, err := st.MailStats(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		return err
	}
	fmt.Printf("queue: %d waiting (%d retrying); last 24 hours: %d sent, %d failed or expired\n", stats.Pending, stats.Retrying, stats.Sent, stats.Failed)
	rows, err := st.MailLog(ctx, 20)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "QUEUED\tID\tKIND\tDOMAIN\tSTATUS\tATTEMPTS\tERROR")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.CreatedAt.Format("2006-01-02 15:04:05"), r.ID[:min(12, len(r.ID))], r.Kind,
			r.RecipientDomain, r.Status, r.Attempts, r.Error)
	}
	return tw.Flush()
}
