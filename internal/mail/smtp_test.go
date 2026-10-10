package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor/internal/config"
)

// fakeRelay is a minimal SMTP server for the tests: EHLO, optional
// STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA, QUIT.
type fakeRelay struct {
	ln       net.Listener
	tlsConf  *tls.Config
	starttls bool // offer STARTTLS
	implicit bool // the listener speaks TLS from the start
	// rcptCode answers RCPT TO (250 by default).
	rcptCode int
	user, pw string

	mu       sync.Mutex
	messages []relayed
	authTLS  []bool // per AUTH: was the connection encrypted
	commands []string
}

type relayed struct {
	from, to string
	data     string
	tls      bool
}

// testCert is a self-signed certificate for 127.0.0.1 and localhost; its
// PEM is written to a file usable as mail.ca_file.
func testCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

func startRelay(t *testing.T, r *fakeRelay) *fakeRelay {
	t.Helper()
	var err error
	if r.implicit {
		r.ln, err = tls.Listen("tcp", "127.0.0.1:0", r.tlsConf)
	} else {
		r.ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.ln.Close() })
	go func() {
		for {
			c, err := r.ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *fakeRelay) port() int { return r.ln.Addr().(*net.TCPAddr).Port }

func (r *fakeRelay) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, encrypted := c.(*tls.Conn)
	br := bufio.NewReader(c)
	reply := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	reply("220 relay.test ESMTP")
	var cur relayed
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		r.mu.Lock()
		r.commands = append(r.commands, verb)
		r.mu.Unlock()
		switch verb {
		case "EHLO", "HELO":
			lines := []string{"250-relay.test"}
			if r.starttls && !encrypted {
				lines = append(lines, "250-STARTTLS")
			}
			lines = append(lines, "250 AUTH PLAIN")
			for _, l := range lines {
				reply(l)
			}
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(c, r.tlsConf)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, encrypted, br = tc, true, bufio.NewReader(tc)
		case "AUTH":
			parts := strings.Fields(line)
			ok := false
			if len(parts) == 3 {
				raw, _ := base64.StdEncoding.DecodeString(parts[2])
				f := strings.Split(string(raw), "\x00")
				ok = len(f) == 3 && f[1] == r.user && f[2] == r.pw
			}
			r.mu.Lock()
			r.authTLS = append(r.authTLS, encrypted)
			r.mu.Unlock()
			if ok {
				reply("235 ok")
			} else {
				reply("535 bad credentials")
			}
		case "MAIL":
			cur = relayed{from: line, tls: encrypted}
			reply("250 ok")
		case "RCPT":
			r.mu.Lock()
			code := r.rcptCode
			r.mu.Unlock()
			if code == 0 {
				code = 250
			}
			cur.to = line
			reply(strconv.Itoa(code) + " rcpt")
		case "DATA":
			reply("354 go")
			var b strings.Builder
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			cur.data = b.String()
			r.mu.Lock()
			r.messages = append(r.messages, cur)
			r.mu.Unlock()
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func (r *fakeRelay) got() ([]relayed, []bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]relayed(nil), r.messages...), append([]bool(nil), r.authTLS...), append([]string(nil), r.commands...)
}

func relayConfig(port int, security string) config.Mail {
	return config.Mail{Host: "127.0.0.1", Port: port, Security: security, From: "Example Org <no-reply@example.com>",
		ReplyTo: "help@example.com", HelloName: "conductor.test", MaxPerHour: 200}
}

func testMessage() Message {
	return Message{Kind: TemplateTest, To: "Ana Souza <ana@example.org>", Subject: "Olá, teste", Text: "plain body\n.leading dot\n",
		HTML: "<p>html body</p>"}
}

// parsed checks the RFC 5322 message and returns its headers and parts.
func parsed(t *testing.T, data string) (mail.Header, map[string]string) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("message does not parse: %v\n%s", err, data)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q %v", msg.Header.Get("Content-Type"), err)
	}
	parts := map[string]string{}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p) // multipart decodes quoted-printable
		ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		parts[ct] = string(b)
	}
	return msg.Header, parts
}

func TestSendPlainToLoopbackWithAuth(t *testing.T) {
	r := startRelay(t, &fakeRelay{user: "relay-user", pw: "relay-pw"})
	cfg := relayConfig(r.port(), config.MailNone)
	cfg.Username = "relay-user"
	s, err := NewSMTP(cfg, []byte("relay-pw"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.Describe(), "relay-pw") {
		t.Fatal("Describe shows the password")
	}
	if err := s.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	msgs, auths, _ := r.got()
	if len(msgs) != 1 || len(auths) != 1 || auths[0] {
		t.Fatalf("messages %d, auths %v", len(msgs), auths)
	}
	m := msgs[0]
	if !strings.HasPrefix(m.from, "MAIL FROM:<no-reply@example.com>") {
		t.Fatalf("envelope from %q", m.from)
	}
	if !strings.HasPrefix(m.to, "RCPT TO:<ana@example.org>") {
		t.Fatalf("envelope to %q", m.to)
	}
	h, parts := parsed(t, m.data)
	dec := new(mime.WordDecoder)
	subj, _ := dec.DecodeHeader(h.Get("Subject"))
	if subj != "Olá, teste" {
		t.Fatalf("subject %q", subj)
	}
	for _, k := range []string{"From", "To", "Reply-To", "Date", "Message-ID", "MIME-Version"} {
		if h.Get(k) == "" {
			t.Errorf("header %s missing", k)
		}
	}
	if h.Get("Auto-Submitted") != "auto-generated" || h.Get("Precedence") != "" {
		t.Errorf("Auto-Submitted %q Precedence %q", h.Get("Auto-Submitted"), h.Get("Precedence"))
	}
	if _, err := h.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	if !strings.HasSuffix(h.Get("Message-ID"), "@example.com>") {
		t.Errorf("Message-ID %q", h.Get("Message-ID"))
	}
	if !strings.Contains(parts["text/plain"], ".leading dot") || parts["text/html"] != "<p>html body</p>" {
		t.Fatalf("parts %q", parts)
	}
}

func TestSendSTARTTLS(t *testing.T) {
	cert, caFile := testCert(t)
	r := startRelay(t, &fakeRelay{starttls: true, tlsConf: &tls.Config{Certificates: []tls.Certificate{cert}}, user: "u", pw: "p"})
	cfg := relayConfig(r.port(), config.MailSTARTTLS)
	cfg.CAFile, cfg.Username = caFile, "u"
	s, err := NewSMTP(cfg, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	msgs, auths, _ := r.got()
	if len(msgs) != 1 || !msgs[0].tls || len(auths) != 1 || !auths[0] {
		t.Fatalf("STARTTLS not used: messages %+v auths %v", msgs, auths)
	}

	// Without the extra CA the relay's certificate is not trusted: no
	// fallback to plain text.
	cfg.CAFile = ""
	s, _ = NewSMTP(cfg, []byte("p"))
	if err := s.Send(context.Background(), testMessage()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if msgs, auths, _ := r.got(); len(msgs) != 1 || len(auths) != 1 {
		t.Fatalf("something was sent after a failed handshake: %d messages, %d auths", len(msgs), len(auths))
	}
}

func TestSendSTARTTLSNeverDowngraded(t *testing.T) {
	r := startRelay(t, &fakeRelay{user: "u", pw: "p"}) // no STARTTLS offered
	cfg := relayConfig(r.port(), config.MailSTARTTLS)
	cfg.Username = "u"
	s, err := NewSMTP(cfg, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), testMessage())
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("relay without STARTTLS: %v", err)
	}
	_, auths, cmds := r.got()
	if len(auths) != 0 || strings.Contains(strings.Join(cmds, " "), "MAIL") {
		t.Fatalf("commands after a missing STARTTLS: %v", cmds)
	}
}

func TestSendImplicitTLS(t *testing.T) {
	cert, caFile := testCert(t)
	r := startRelay(t, &fakeRelay{implicit: true, tlsConf: &tls.Config{Certificates: []tls.Certificate{cert}}})
	cfg := relayConfig(r.port(), config.MailTLS)
	cfg.CAFile = caFile
	s, err := NewSMTP(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	if msgs, _, _ := r.got(); len(msgs) != 1 || !msgs[0].tls {
		t.Fatalf("%+v", msgs)
	}
}

func TestPlainRefusedOffLoopback(t *testing.T) {
	cfg := relayConfig(25, config.MailNone)
	cfg.Host = "smtp.example.com"
	if _, err := NewSMTP(cfg, nil); err == nil {
		t.Fatal("plain SMTP to a remote relay accepted")
	}
	// Defence in depth: even if the sender were built for a remote relay
	// without TLS, the password is never sent in clear text.
	r := startRelay(t, &fakeRelay{user: "u", pw: "p"})
	cfg = relayConfig(r.port(), config.MailSTARTTLS)
	cfg.Host, cfg.Username = "smtp.example.com", "u"
	s, err := NewSMTP(cfg, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	s.security = config.MailNone
	addr := r.ln.Addr().String()
	s.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if err := s.Send(context.Background(), testMessage()); err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Fatalf("password over plain text to a remote relay: %v", err)
	}
	if _, auths, _ := r.got(); len(auths) != 0 {
		t.Fatal("AUTH was sent")
	}
}

func TestSendRecipientRefused(t *testing.T) {
	r := startRelay(t, &fakeRelay{rcptCode: 550})
	s, err := NewSMTP(relayConfig(r.port(), config.MailNone), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testMessage()); !errors.Is(err, ErrRecipientRefused) {
		t.Fatalf("550: %v", err)
	}
	r.mu.Lock()
	r.rcptCode = 450
	r.mu.Unlock()
	if err := s.Send(context.Background(), testMessage()); err == nil || errors.Is(err, ErrRecipientRefused) {
		t.Fatalf("450 is temporary: %v", err)
	}
}

func TestHeaderInjectionRefused(t *testing.T) {
	for _, to := range []string{"a@example.com\r\nBcc: x@example.net", "a@example.com\nBcc: x@example.net", "a@example.com, b@example.net",
		"", "nobody", "a@", strings.Repeat("a", 250) + "@example.com"} {
		if _, err := ParseRecipient(to); err == nil {
			t.Errorf("recipient %q accepted", to)
		}
		if _, err := Compose(&mail.Address{Address: "no-reply@example.com"}, nil, Message{To: to, Subject: "s", Text: "t", HTML: "h"}, time.Now()); err == nil {
			t.Errorf("compose to %q accepted", to)
		}
	}
	// A subject or sender name with line breaks never starts a header.
	m := Message{To: "a@example.com", Subject: "hello\r\nBcc: x@example.net\r\n\r\nbody", Text: "t", HTML: "h"}
	b, err := Compose(&mail.Address{Name: "Org", Address: "no-reply@example.com"}, nil, m, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(b), "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "bcc:") {
			t.Fatalf("injected header: %q", l)
		}
	}
	if _, err := Compose(&mail.Address{Name: "Org\r\nBcc: x@example.net", Address: "no-reply@example.com"}, nil, m, time.Now()); err == nil {
		t.Fatal("sender name with a line break accepted")
	}
	if got := headerValue("a\r\nb\x00c"); strings.ContainsAny(got, "\r\n\x00") {
		t.Fatalf("headerValue %q", got)
	}
}

func TestLoadPassword(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := LoadPassword(p); err != nil || string(b) != "secret" {
		t.Fatalf("%q %v", b, err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPassword(p); err == nil {
		t.Fatal("world-readable password file accepted")
	}
	two := filepath.Join(dir, "two")
	_ = os.WriteFile(two, []byte("a\nb\n"), 0o600)
	if _, err := LoadPassword(two); err == nil {
		t.Fatal("two lines accepted")
	}
	if b, err := LoadPassword(""); err != nil || b != nil {
		t.Fatal("empty path")
	}
	cfg := relayConfig(25, config.MailNone)
	cfg.Username = "u"
	if _, err := NewSMTP(cfg, nil); err == nil {
		t.Fatal("username without a password accepted")
	}
}

func TestRedact(t *testing.T) {
	got := redact("550 5.1.1 <ana@example.org>: Recipient address rejected\r\nmore")
	if strings.Contains(got, "ana@") || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("redact %q", got)
	}
	if Domain("Ana <ana@Example.ORG>") != "example.org" || Domain("x") != "" {
		t.Fatal("Domain")
	}
}
