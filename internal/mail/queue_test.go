package mail

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// fakeSender records deliveries; fail decides the outcome of each.
type fakeSender struct {
	mu   sync.Mutex
	sent []Message
	fail func(Message) error
}

func (f *fakeSender) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		if err := f.fail(m); err != nil {
			return err
		}
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

type queueHarness struct {
	q      *Queue
	st     *store.Store
	box    *secret.Box
	sender *fakeSender
	now    time.Time
	logs   *bytes.Buffer
}

func newQueueHarness(t *testing.T, maxPerHour int) *queueHarness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secret.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	h := &queueHarness{st: st, box: box, sender: &fakeSender{}, now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), logs: &bytes.Buffer{}}
	h.q = NewQueue(st, box, h.sender, QueueOptions{MaxPerHour: maxPerHour, Logger: slog.New(slog.NewTextHandler(h.logs, nil)),
		Now: func() time.Time { return h.now }})
	return h
}

func (h *queueHarness) enqueue(t *testing.T, to string, life time.Duration) string {
	t.Helper()
	id, err := h.q.Enqueue(context.Background(), Message{Kind: TemplateReset, To: to, Subject: "Reset your password",
		Text: "secret link https://x.example/link/TOKEN", HTML: "<a href=\"https://x.example/link/TOKEN\">x</a>"}, h.now.Add(life), "tok_123")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *queueHarness) process(t *testing.T) int {
	t.Helper()
	n, err := h.q.Process(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (h *queueHarness) logRow(t *testing.T, id string) store.MailLogRow {
	t.Helper()
	r, err := h.st.GetMailLog(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestQueueSealsAndDelivers(t *testing.T) {
	h := newQueueHarness(t, 200)
	ctx := context.Background()
	id := h.enqueue(t, "Ana <ana@Example.org>", time.Hour)

	rows, err := h.st.DueMail(ctx, h.now, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %d", err, len(rows))
	}
	r := rows[0]
	for _, b := range [][]byte{r.RecipientSealed, r.SubjectSealed, r.TextSealed, r.HTMLSealed} {
		if bytes.Contains(b, []byte("ana@")) || bytes.Contains(b, []byte("TOKEN")) || bytes.Contains(b, []byte("Reset")) {
			t.Fatal("queued content in clear text")
		}
	}
	// Sealed content is bound to its id.
	if _, err := h.box.Open(r.TextSealed, aad(r.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.box.Open(r.TextSealed, aad("other")); err == nil {
		t.Fatal("content opens under another id")
	}
	if lr := h.logRow(t, id); lr.Status != store.MailQueued || lr.RecipientDomain != "example.org" || lr.Reference != "tok_123" {
		t.Fatalf("log %+v", lr)
	}

	if n := h.process(t); n != 1 {
		t.Fatalf("sent %d", n)
	}
	if h.sender.sent[0].To != "Ana <ana@Example.org>" || !strings.Contains(h.sender.sent[0].Text, "TOKEN") {
		t.Fatalf("delivered %+v", h.sender.sent[0])
	}
	lr := h.logRow(t, id)
	if lr.Status != store.MailSent || lr.Attempts != 1 || lr.SentAt.IsZero() {
		t.Fatalf("log after sending %+v", lr)
	}
	if rows, _ := h.st.DueMail(ctx, h.now.Add(time.Hour), 10); len(rows) != 0 {
		t.Fatal("sent message still queued")
	}
	// The service log carries neither the address nor the content.
	if l := h.logs.String(); strings.Contains(l, "ana@") || strings.Contains(l, "TOKEN") || strings.Contains(l, "Reset your") {
		t.Fatalf("log leaks content:\n%s", l)
	}
	st, err := h.q.Stats(ctx)
	if err != nil || st.Sent != 1 || st.Pending != 0 {
		t.Fatalf("stats %+v %v", st, err)
	}
}

func TestQueueRetryBackoff(t *testing.T) {
	h := newQueueHarness(t, 200)
	h.sender.fail = func(Message) error { return errors.New("451 4.3.0 try later for <ana@example.org>") }
	start := h.now
	id := h.enqueue(t, "ana@example.org", 3*time.Hour)
	// Waits after each failure: 1, 2, 4, 8, 16 minutes, then 30.
	waits := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	attempts := 0
	for i, w := range waits {
		h.process(t) // an attempt at h.now
		attempts++
		lr := h.logRow(t, id)
		if lr.Status != store.MailRetrying || lr.Attempts != attempts {
			t.Fatalf("attempt %d: %+v", i+1, lr)
		}
		if strings.Contains(lr.Error, "ana@") {
			t.Fatalf("error keeps the address: %q", lr.Error)
		}
		// Just before the wait ends nothing is attempted.
		h.now = h.now.Add(w*time.Minute - time.Second)
		h.process(t)
		if got := h.logRow(t, id).Attempts; got != attempts {
			t.Fatalf("attempt %d: retried after %v, before the %v wait", i+1, w*time.Minute-time.Second, w*time.Minute)
		}
		h.now = h.now.Add(time.Second)
	}
	if h.now.Sub(start) != 91*time.Minute {
		t.Fatalf("elapsed %v", h.now.Sub(start))
	}
	// Then it succeeds.
	h.sender.fail = nil
	if n := h.process(t); n != 1 {
		t.Fatal("not delivered after the retries")
	}
	if lr := h.logRow(t, id); lr.Status != store.MailSent || lr.Attempts != len(waits)+1 || lr.Error != "" {
		t.Fatalf("%+v", lr)
	}
}

func TestQueueExpiry(t *testing.T) {
	h := newQueueHarness(t, 200)
	h.sender.fail = func(Message) error { return errors.New("connection refused") }
	id := h.enqueue(t, "ana@example.org", NotificationLifetime)
	for h.logRow(t, id).Status != store.MailExpired {
		h.process(t)
		h.now = h.now.Add(10 * time.Minute)
		if h.now.After(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)) {
			t.Fatal("never expired")
		}
	}
	lr := h.logRow(t, id)
	// 24 hours: the quick retries in the first hour, then every 30 minutes
	// (passes every 10 minutes here: 51 attempts).
	if lr.Attempts < 45 || lr.Attempts > 55 || lr.Error == "" {
		t.Fatalf("expired row %+v", lr)
	}
	if rows, _ := h.st.DueMail(context.Background(), h.now.Add(48*time.Hour), 10); len(rows) != 0 {
		t.Fatal("expired message still queued")
	}
	if st, _ := h.q.Stats(context.Background()); st.Failed != 1 || st.Pending != 0 {
		t.Fatalf("stats %+v", st)
	}

	// A message whose time is up before the relay is reached is never sent.
	h.sender.fail = nil
	id = h.enqueue(t, "bob@example.org", time.Minute)
	h.now = h.now.Add(time.Minute)
	if n := h.process(t); n != 0 || h.sender.count() != 0 || h.logRow(t, id).Status != store.MailExpired {
		t.Fatal("expired message sent")
	}
}

func TestQueueRecipientRefusedIsFinal(t *testing.T) {
	h := newQueueHarness(t, 200)
	h.sender.fail = func(Message) error { return ErrRecipientRefused }
	id := h.enqueue(t, "nobody@example.org", time.Hour)
	h.process(t)
	if lr := h.logRow(t, id); lr.Status != store.MailFailed || lr.Attempts != 1 {
		t.Fatalf("%+v", lr)
	}
	if rows, _ := h.st.DueMail(context.Background(), h.now.Add(time.Hour), 10); len(rows) != 0 {
		t.Fatal("refused message still queued")
	}
}

func TestQueueUndecryptableIsDropped(t *testing.T) {
	h := newQueueHarness(t, 200)
	id := h.enqueue(t, "ana@example.org", time.Hour)
	// The state key changed (a restore with another key).
	other, _ := secret.NewRandom()
	h.q.box = other
	h.process(t)
	if lr := h.logRow(t, id); lr.Status != store.MailFailed || h.sender.count() != 0 {
		t.Fatalf("%+v", lr)
	}
}

func TestQueueHourlyCeiling(t *testing.T) {
	h := newQueueHarness(t, 3)
	for range 5 {
		h.enqueue(t, "ana@example.org", 4*time.Hour)
		h.now = h.now.Add(time.Second)
	}
	if n := h.process(t); n != 3 {
		t.Fatalf("first pass sent %d", n)
	}
	if n := h.process(t); n != 0 {
		t.Fatalf("over the ceiling: %d", n)
	}
	if !strings.Contains(h.logs.String(), "hourly ceiling reached") {
		t.Fatalf("no alert in the log:\n%s", h.logs.String())
	}
	// The alert is not repeated on every pass.
	h.process(t)
	if c := strings.Count(h.logs.String(), "hourly ceiling reached"); c != 1 {
		t.Fatalf("%d alerts", c)
	}
	if st, _ := h.q.Stats(context.Background()); st.Pending != 2 {
		t.Fatalf("pending %d", st.Pending)
	}
	h.now = h.now.Add(time.Hour + time.Second)
	if n := h.process(t); n != 2 {
		t.Fatalf("after an hour sent %d", n)
	}
}

func TestEnqueueRefuses(t *testing.T) {
	h := newQueueHarness(t, 200)
	ctx := context.Background()
	ok := Message{Kind: TemplateTest, To: "a@example.org", Subject: "s", Text: "t", HTML: "h"}
	cases := map[string]func() (Message, time.Time, string){
		"header injection": func() (Message, time.Time, string) {
			m := ok
			m.To = "a@example.org\r\nBcc: x@example.net"
			return m, h.now.Add(time.Hour), ""
		},
		"bad kind": func() (Message, time.Time, string) {
			m := ok
			m.Kind = "Test Kind"
			return m, h.now.Add(time.Hour), ""
		},
		"bad reference": func() (Message, time.Time, string) { return ok, h.now.Add(time.Hour), "ana@example.org has spaces" },
		"expired":       func() (Message, time.Time, string) { return ok, h.now, "" },
		"no body": func() (Message, time.Time, string) {
			m := ok
			m.HTML = ""
			return m, h.now.Add(time.Hour), ""
		},
	}
	for name, c := range cases {
		m, exp, ref := c()
		if _, err := h.q.Enqueue(ctx, m, exp, ref); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A far expiry is capped.
	id, err := h.q.Enqueue(ctx, ok, h.now.Add(30*24*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := h.st.DueMail(ctx, h.now, 10)
	if len(rows) != 1 || rows[0].ID != id || !rows[0].ExpiresAt.Equal(h.now.Add(MaxLifetime)) {
		t.Fatalf("%+v", rows)
	}
}

func TestQueueRunWakesOnEnqueue(t *testing.T) {
	h := newQueueHarness(t, 200)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.q.Run(ctx); close(done) }()
	h.enqueue(t, "ana@example.org", time.Hour)
	deadline := time.Now().Add(5 * time.Second)
	for h.sender.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if h.sender.count() != 1 {
		t.Fatal("worker did not deliver")
	}
}

func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{0: time.Minute, 1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute,
		4: 8 * time.Minute, 5: 16 * time.Minute, 6: 30 * time.Minute, 50: 30 * time.Minute} {
		if got := backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}
