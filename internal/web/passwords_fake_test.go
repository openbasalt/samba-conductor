package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// fakeProv is an in-memory conductor-provisioner: accounts by SID, tokens
// by value, the rules of the real service that conductor relies on.
type fakeProv struct {
	mu     sync.Mutex
	now    func() time.Time
	users  map[string]*provapi.UserResult // by SID
	tokens map[string]*fakeToken          // by raw token
	reqs   []provapi.Request
	n      int
	// fail makes an operation answer an error.
	fail map[provapi.Op]*provapi.Error
	// policy makes password.set answer password_policy with this reason.
	policy string
	// passwords set, by SID (never compared, only recorded).
	set    map[string]bool
	unlock map[string]bool
}

type fakeToken struct {
	id, purpose, sid, state string
	expires                 time.Time
	passwordSet             bool
}

func newFakeProv(now func() time.Time) *fakeProv {
	f := &fakeProv{now: now, tokens: map[string]*fakeToken{}, fail: map[provapi.Op]*provapi.Error{}, set: map[string]bool{},
		unlock: map[string]bool{}, users: map[string]*provapi.UserResult{}}
	for _, u := range []provapi.UserResult{
		{SID: testDomain + "-1101", SAM: "normal.user", DN: "CN=normal.user,OU=People,DC=lab,DC=test", Mail: "normal.user@example.org", Enabled: true, InScope: true},
		{SID: testDomain + "-1201", SAM: "new.person", DN: "CN=new.person,OU=People,DC=lab,DC=test", Mail: "new.person@example.org", InScope: true},
		{SID: testDomain + "-1202", SAM: "priv.user", DN: "CN=priv.user,OU=People,DC=lab,DC=test", Mail: "priv.user@example.org", Enabled: true,
			InScope: true, Privileged: true, PrivilegedReasons: []string{"group"}},
		{SID: testDomain + "-1203", SAM: "outside.user", DN: "CN=outside.user,CN=Users,DC=lab,DC=test", Mail: "outside@example.org", Enabled: true},
		{SID: testDomain + "-1204", SAM: "nomail.user", DN: "CN=nomail.user,OU=People,DC=lab,DC=test", Enabled: true, InScope: true},
	} {
		u.PrivilegedReasons = append([]string{}, u.PrivilegedReasons...)
		u.PendingTokens = []provapi.PendingToken{}
		f.users[u.SID] = &u
	}
	return f
}

func (f *fakeProv) Call(_ context.Context, req provapi.Request) (provapi.Response, error) {
	p, err := req.Decode()
	if err != nil {
		return provapi.Response{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	if e := f.fail[req.Op]; e != nil {
		return provapi.ErrorResponse(req.ID, e), e
	}
	res, perr := f.handle(req, p)
	if perr != nil {
		return provapi.ErrorResponse(req.ID, perr), perr
	}
	return provapi.OKResponse(req.ID, res)
}

func perr(code provapi.ErrorCode) *provapi.Error {
	return &provapi.Error{Code: code, Message: string(code)}
}

// target applies the invariants of the real service.
func (f *fakeProv) target(sid string) (*provapi.UserResult, *provapi.Error) {
	u := f.users[sid]
	switch {
	case u == nil:
		return nil, perr(provapi.CodeNotFound)
	case !u.InScope:
		return nil, perr(provapi.CodeOutOfScope)
	case u.Privileged:
		e := perr(provapi.CodePrivileged)
		e.Kinds = u.PrivilegedReasons
		return nil, e
	}
	return u, nil
}

func (f *fakeProv) token(raw string) (*fakeToken, *provapi.UserResult, *provapi.Error) {
	t := f.tokens[raw]
	if t == nil {
		return nil, nil, perr(provapi.CodeNotFound)
	}
	switch {
	case t.state == provapi.StateUsed:
		return nil, nil, perr(provapi.CodeUsed)
	case t.state == provapi.StateRevoked:
		return nil, nil, perr(provapi.CodeRevoked)
	case !f.now().Before(t.expires):
		t.state = provapi.StateExpired
		return nil, nil, perr(provapi.CodeExpired)
	}
	u, e := f.target(t.sid)
	if e != nil {
		return nil, nil, e
	}
	return t, u, nil
}

func (f *fakeProv) handle(req provapi.Request, p provapi.Params) (any, *provapi.Error) {
	switch q := p.(type) {
	case *provapi.NoParams:
		return provapi.StatusResult{Version: "test", Account: "svc-conductor-prov", ScopeOUs: []string{"OU=People,DC=lab,DC=test"}}, nil
	case *provapi.UserCheckParams:
		u := f.users[q.SID]
		if u == nil {
			return nil, perr(provapi.CodeNotFound)
		}
		return u, nil
	case *provapi.UserFindParams:
		for _, u := range f.users {
			if strings.EqualFold(u.SAM, q.UsernameOrMail) || (u.Mail != "" && strings.EqualFold(u.Mail, q.UsernameOrMail)) {
				return u, nil
			}
		}
		return nil, perr(provapi.CodeNotFound)
	case *provapi.TokenIssueParams:
		u, e := f.target(q.SID)
		if e != nil {
			return nil, e
		}
		if q.Purpose == provapi.PurposeReset && !u.Enabled && !u.Locked {
			return nil, perr(provapi.CodeInvalidParams)
		}
		for _, t := range f.tokens {
			if t.sid == q.SID && t.purpose == q.Purpose && (t.state == provapi.StateOpen || t.state == provapi.StatePasswordSet) {
				t.state = provapi.StateRevoked
			}
		}
		f.n++
		raw := fmt.Sprintf("tok%040d", f.n)
		ttl := 72 * time.Hour
		if q.Purpose == provapi.PurposeReset {
			ttl = 30 * time.Minute
		}
		t := &fakeToken{id: fmt.Sprintf("%032x", f.n), purpose: q.Purpose, sid: q.SID, state: provapi.StateOpen,
			expires: f.now().Add(ttl)}
		f.tokens[raw] = t
		return provapi.TokenIssueResult{Token: raw, TokenID: t.id, ExpiresAt: t.expires, SAM: u.SAM, DN: u.DN, Mail: u.Mail}, nil
	case *provapi.TokenCheckParams:
		t, u, e := f.token(q.Token)
		if e != nil {
			return nil, e
		}
		return provapi.TokenCheckResult{TokenID: t.id, Purpose: t.purpose, SAM: u.SAM, DN: u.DN, Mail: u.Mail, SID: u.SID, ExpiresAt: t.expires,
			PasswordSet: t.passwordSet}, nil
	case *provapi.PasswordSetParams:
		t, u, e := f.token(q.Token)
		if e != nil {
			return nil, e
		}
		if t.passwordSet {
			return nil, perr(provapi.CodeInvalidParams)
		}
		if f.policy != "" {
			e := perr(provapi.CodePasswordPolicy)
			e.Reason = f.policy
			return nil, e
		}
		f.set[u.SID] = true
		f.unlock[u.SID] = q.Unlock
		if t.purpose == provapi.PurposeReset {
			t.state = provapi.StateUsed
		} else {
			t.passwordSet, t.state = true, provapi.StatePasswordSet
		}
		return provapi.PasswordSetResult{SAM: u.SAM, DN: u.DN, Mail: u.Mail, Purpose: t.purpose}, nil
	case *provapi.InviteCompleteParams:
		t, u, e := f.token(q.Token)
		if e != nil {
			return nil, e
		}
		if !t.passwordSet || t.purpose != provapi.PurposeInvite {
			return nil, perr(provapi.CodeInvalidParams)
		}
		t.state = provapi.StateUsed
		u.Enabled = true
		return provapi.InviteCompleteResult{SAM: u.SAM, DN: u.DN}, nil
	case *provapi.TokenRevokeParams:
		n := 0
		for _, t := range f.tokens {
			if t.sid == q.SID && (q.Purpose == "" || t.purpose == q.Purpose) && (t.state == provapi.StateOpen || t.state == provapi.StatePasswordSet) {
				t.state = provapi.StateRevoked
				n++
			}
		}
		return provapi.TokenRevokeResult{Revoked: n}, nil
	case *provapi.TokenListParams:
		out := []provapi.TokenInfo{}
		for _, t := range f.tokens {
			if t.sid == q.SID {
				state := t.state
				if state == provapi.StateOpen && !f.now().Before(t.expires) {
					state = provapi.StateExpired
				}
				out = append(out, provapi.TokenInfo{TokenID: t.id, Purpose: t.purpose, ExpiresAt: t.expires, State: state, IssuedBy: req.Actor.String()})
			}
		}
		return out, nil
	}
	return nil, perr(provapi.CodeInvalidParams)
}

// count returns how many requests of an operation were made.
func (f *fakeProv) count(op provapi.Op) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if r.Op == op {
			n++
		}
	}
	return n
}

// last returns the last request of an operation.
func (f *fakeProv) last(op provapi.Op) *provapi.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.reqs) - 1; i >= 0; i-- {
		if f.reqs[i].Op == op {
			r := f.reqs[i]
			return &r
		}
	}
	return nil
}

// pwHarness is a harness with mail, the fake provisioner and a public URL.
type pwHarness struct {
	*harness
	prov   *fakeProv
	mailBx *secret.Box
}

func newPWHarness(t *testing.T, mutate ...func(*config.Config)) *pwHarness {
	t.Helper()
	all := append([]func(*config.Config){func(c *config.Config) {
		c.Server.PublicURL = "https://conductor.test"
		c.Mail = config.Mail{Host: "smtp.example.com", Port: 587, Security: config.MailSTARTTLS, From: "no-reply@example.com", MaxPerHour: 1000}
		c.Provisioner = config.Provisioner{Enabled: true, Socket: "/run/conductor-provisioner/api.sock"}
	}}, mutate...)
	h := newHarness(t, all...)
	box, err := secret.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	h.s.mailq = mail.NewQueue(h.st, box, nil, mail.QueueOptions{MaxPerHour: 1000, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return h.now }})
	fp := newFakeProv(func() time.Time { return h.now })
	h.s.prov = fp
	return &pwHarness{harness: h, prov: fp, mailBx: box}
}

// sentMail is a queued message, opened.
type sentMail struct {
	Kind, To, Subject, Text string
	Reference               string
}

// mails returns the queued messages, oldest first.
func (h *pwHarness) mails(t *testing.T) []sentMail {
	t.Helper()
	rows, err := h.st.DueMail(context.Background(), h.now.Add(time.Hour), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []sentMail
	for _, r := range rows {
		open := func(b []byte) string {
			v, err := h.mailBx.Open(b, []byte("mail:"+r.ID))
			if err != nil {
				t.Fatal(err)
			}
			return string(v)
		}
		out = append(out, sentMail{Kind: r.Kind, To: open(r.RecipientSealed), Subject: open(r.SubjectSealed), Text: open(r.TextSealed), Reference: r.Reference})
	}
	return out
}

// mailsOf filters the queued messages by kind.
func (h *pwHarness) mailsOf(t *testing.T, kind string) []sentMail {
	var out []sentMail
	for _, m := range h.mails(t) {
		if m.Kind == kind {
			out = append(out, m)
		}
	}
	return out
}

// setSettings stores password settings directly.
func (h *pwHarness) setSettings(t *testing.T, mutate func(*passwordSettings)) {
	t.Helper()
	p := defaultPasswordSettings()
	mutate(&p)
	if err := h.st.PutSettings(context.Background(), p.values(), "test"); err != nil {
		t.Fatal(err)
	}
}

// browser is a cookie jar for the anonymous link and reset pages.
type browser struct {
	h       *pwHarness
	cookies map[string]string
	ip      string
}

func (h *pwHarness) browser() *browser {
	return &browser{h: h, cookies: map[string]string{}, ip: "198.51.100.7"}
}

// do sends a request with the jar's cookies; a POST carries the CSRF token
// of the link record or the pre-session cookie unless the form has one.
func (b *browser) do(method, path string, form url.Values) *http.Response {
	if method == http.MethodPost {
		if form == nil {
			form = url.Values{}
		}
		if b.cookies[preCookie] == "" && b.cookies[linkCookie] == "" {
			// Like a browser that saw a form first: the pre-session cookie.
			b.do("GET", "/signin", nil)
		}
		if _, ok := form["csrf"]; !ok {
			form.Set("csrf", b.csrf())
		}
	}
	w := b.h.do(method, path, "", form, func(r *http.Request) {
		r.RemoteAddr = b.ip + ":40000"
		for k, v := range b.cookies {
			r.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	})
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return w.Result()
}

func (b *browser) csrf() string {
	if c := b.cookies[linkCookie]; c != "" {
		if rec := b.h.s.links.get(c, b.h.now); rec != nil {
			return rec.sess.csrf
		}
	}
	return b.cookies[preCookie]
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// linkFrom extracts the link path of a message.
func linkFrom(t *testing.T, text string) string {
	t.Helper()
	i := strings.Index(text, "https://conductor.test/link/")
	if i < 0 {
		t.Fatalf("no link in %q", text)
	}
	rest := text[i+len("https://conductor.test"):]
	if j := strings.IndexAny(rest, " \n\r"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// auditActions lists the audited actions with their result.
func (h *pwHarness) auditActions(t *testing.T) []string {
	t.Helper()
	evs, _, err := h.st.ListAudit(context.Background(), store.AuditFilter{}, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(evs) - 1; i >= 0; i-- {
		out = append(out, evs[i].Action+":"+evs[i].Result)
	}
	return out
}

func hasAction(list []string, want string) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

// jsonOf is a compact rendering for failure messages.
func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
