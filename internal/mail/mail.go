// Package mail is conductor's outgoing e-mail: an SMTP sender (STARTTLS or
// implicit TLS; plain SMTP only to a loopback relay), a queue in SQLite
// whose recipient, subject and bodies are sealed under the state key, and
// the message templates (plain text and HTML, en and pt-BR) with the
// organization's branding.
//
// Messages never carry a password or account status; the queue keeps a
// message only until the relay accepts it or it expires, and the log keeps
// no content and no recipient beyond its domain.
package mail

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// Message is one e-mail to one recipient.
type Message struct {
	// Kind is the template the message was made from (test, invitation,
	// ...): logged, never the content.
	Kind    string
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender delivers a message to the relay.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// ErrRecipientRefused wraps a permanent refusal of the recipient by the
// relay (5xx to RCPT TO): the message is not retried.
var ErrRecipientRefused = errors.New("mail: recipient refused")

// ParseRecipient checks a recipient address: one address, no control
// characters (header injection), a domain part, at most 254 characters.
func ParseRecipient(s string) (*mail.Address, error) {
	if s == "" || len(s) > 254 || hasControl(s) {
		return nil, fmt.Errorf("mail: invalid recipient")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("mail: invalid recipient: %w", err)
	}
	at := strings.LastIndexByte(a.Address, '@')
	if at < 1 || at == len(a.Address)-1 || strings.ContainsAny(a.Address, " <>,;") {
		return nil, fmt.Errorf("mail: invalid recipient")
	}
	return a, nil
}

// Domain returns the domain of an address (lower-cased), or "" when it
// has none. Logs and the audit carry it instead of the address.
func Domain(addr string) string {
	a, err := mail.ParseAddress(addr)
	if err != nil {
		return ""
	}
	at := strings.LastIndexByte(a.Address, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(a.Address[at+1:])
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// headerValue strips line breaks (and other control characters) from a
// header value, so a value can never start a header of its own.
func headerValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

var addressRE = regexp.MustCompile(`[^\s<>"'(),;:]+@[^\s<>"'(),;:]+`)

// redact removes e-mail addresses from an error text before it is logged
// or stored (relays quote the recipient in their refusals).
func redact(s string) string {
	s = addressRE.ReplaceAllString(s, "[address]")
	s = headerValue(s)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
