package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/secret"
)

// sendTimeout bounds one delivery (connection, TLS, SMTP dialogue).
const sendTimeout = 60 * time.Second

// SMTP delivers messages to the configured relay. Safe for concurrent use.
type SMTP struct {
	addr     string // host:port
	host     string
	security string
	username string
	// password is sealed under a per-process key while it sits in memory.
	password []byte
	pwBox    *secret.Box
	from     *mail.Address
	replyTo  *mail.Address
	hello    string
	tls      *tls.Config
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	now      func() time.Time
}

// NewSMTP builds the sender for [mail]; password is the relay password
// (nil without authentication). The caller may clear its copy afterwards.
func NewSMTP(m config.Mail, password []byte) (*SMTP, error) {
	if !m.Enabled() {
		return nil, errors.New("mail: no relay configured (mail.host)")
	}
	switch m.Security {
	case config.MailSTARTTLS, config.MailTLS:
	case config.MailNone:
		if !loopbackHost(m.Host) {
			// Never links or a password in clear text over a network.
			return nil, errors.New("mail: plain SMTP (security = \"none\") is only allowed to a loopback relay")
		}
	default:
		return nil, fmt.Errorf("mail: unknown security %q", m.Security)
	}
	from, err := mail.ParseAddress(m.From)
	if err != nil {
		return nil, fmt.Errorf("mail: from: %w", err)
	}
	s := &SMTP{addr: net.JoinHostPort(m.Host, strconv.Itoa(m.Port)), host: m.Host, security: m.Security, username: m.Username,
		from: from, hello: m.HelloName, now: time.Now}
	if m.ReplyTo != "" {
		if s.replyTo, err = mail.ParseAddress(m.ReplyTo); err != nil {
			return nil, fmt.Errorf("mail: reply_to: %w", err)
		}
	}
	if s.hello == "" {
		if s.hello, err = os.Hostname(); err != nil || s.hello == "" {
			s.hello = "localhost"
		}
	}
	pool, err := certPool(m.CAFile)
	if err != nil {
		return nil, err
	}
	s.tls = &tls.Config{ServerName: m.Host, RootCAs: pool, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: 20 * time.Second}
	s.dial = d.DialContext
	if m.Username != "" {
		if len(password) == 0 {
			return nil, errors.New("mail: mail.username is set but the password is empty")
		}
		if s.pwBox, err = secret.NewRandom(); err != nil {
			return nil, err
		}
		if s.password, err = s.pwBox.Seal(password, []byte("smtp")); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// certPool is the system roots plus an extra CA file.
func certPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile == "" {
		return pool, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("mail: ca_file: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("mail: ca_file %s holds no PEM certificate", caFile)
	}
	return pool, nil
}

// LoadPassword reads the relay password from path (mail.password_file or
// the systemd credential): one line, trailing line break removed. The
// file must not be readable by others.
func LoadPassword(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("mail: password: %w", err)
	}
	if st.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("mail: password file %s is readable by others (mode %v); use 0600 or 0640", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mail: password: %w", err)
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 || bytes.ContainsAny(b, "\r\n\x00") {
		return nil, fmt.Errorf("mail: password file %s must hold one non-empty line", path)
	}
	return b, nil
}

// Compose renders the RFC 5322 message: multipart/alternative with the
// text and HTML parts, quoted-printable. Header values cannot break a
// line; an invalid recipient is refused.
func Compose(from, replyTo *mail.Address, m Message, now time.Time) ([]byte, error) {
	to, err := ParseRecipient(m.To)
	if err != nil {
		return nil, err
	}
	if from == nil || hasControl(from.Address) || hasControl(from.Name) {
		return nil, errors.New("mail: invalid sender")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	boundary := make([]byte, 16)
	if _, err := rand.Read(boundary); err != nil {
		return nil, err
	}
	domain := "localhost"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 {
		domain = from.Address[at+1:]
	}
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + headerValue(v) + "\r\n") }
	h("From", from.String())
	h("To", to.String())
	if replyTo != nil {
		h("Reply-To", replyTo.String())
	}
	h("Subject", mime.QEncoding.Encode("utf-8", headerValue(m.Subject)))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	bnd := "conductor-" + hex.EncodeToString(boundary)
	h("Content-Type", `multipart/alternative; boundary="`+bnd+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ ctype, body string }{{"text/plain; charset=utf-8", m.Text}, {"text/html; charset=utf-8", m.HTML}} {
		b.WriteString("--" + bnd + "\r\n")
		b.WriteString("Content-Type: " + part.ctype + "\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
		w := quotedprintable.NewWriter(&b)
		if _, err := w.Write([]byte(strings.ReplaceAll(part.body, "\r\n", "\n"))); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		b.WriteString("\r\n")
	}
	b.WriteString("--" + bnd + "--\r\n")
	return b.Bytes(), nil
}

// Send delivers m: one connection, one recipient.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	to, err := ParseRecipient(m.To)
	if err != nil {
		return err
	}
	body, err := Compose(s.from, s.replyTo, m, s.now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	conn, err := s.dial(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if s.security == config.MailTLS {
		tc := tls.Client(conn, s.tls)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(s.hello); err != nil {
		return err
	}
	if s.security == config.MailSTARTTLS {
		// Required, never downgraded to plain text.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mail: the relay does not offer STARTTLS")
		}
		if err := c.StartTLS(s.tls); err != nil {
			return err
		}
	}
	if s.username != "" {
		pw, err := s.pwBox.Open(s.password, []byte("smtp"))
		if err != nil {
			return err
		}
		// PLAIN only over TLS or to a loopback relay (net/smtp refuses it
		// otherwise too; checked here so it never depends on that).
		if _, tlsOn := c.TLSConnectionState(); !tlsOn && !loopbackHost(s.host) {
			clear(pw)
			return errors.New("mail: refusing to send the password without TLS to a relay that is not on this host")
		}
		err = c.Auth(smtp.PlainAuth("", s.username, string(pw), s.host))
		clear(pw)
		if err != nil {
			return err
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to.Address); err != nil {
		var te *textproto.Error
		if errors.As(err, &te) && te.Code >= 500 {
			return fmt.Errorf("%w: %w", ErrRecipientRefused, err)
		}
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// loopbackHost reports whether host is "localhost" or a loopback address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Describe summarizes the relay for logs and the settings page (never
// the password).
func (s *SMTP) Describe() string {
	auth := "no authentication"
	if s.username != "" {
		auth = "user " + s.username
	}
	return fmt.Sprintf("%s (%s, %s)", s.addr, s.security, auth)
}
