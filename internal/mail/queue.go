package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Bounds of the queue.
const (
	// MaxLifetime is the longest a message may wait for the relay.
	MaxLifetime = 8 * 24 * time.Hour
	// NotificationLifetime is how long a notification waits (messages that
	// carry a link expire with it instead).
	NotificationLifetime = 24 * time.Hour
	// LogRetention is how long the log keeps a finished message.
	LogRetention = 30 * 24 * time.Hour
	// batch is the most messages handed to the relay in one pass.
	batch = 50
	// tick is how often the worker looks at the queue without a wake-up.
	tick = 30 * time.Second
	// alertEvery bounds the ceiling warning in the log.
	alertEvery = 10 * time.Minute
)

// backoff is the wait after the n-th failed attempt: 1, 2, 4, 8 and 16
// minutes, then every 30 minutes until the message expires.
func backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > 5 {
		return 30 * time.Minute
	}
	return time.Duration(1<<(n-1)) * time.Minute
}

// Queue keeps messages in SQLite until the relay accepts them. Recipient,
// subject and bodies are sealed with the state key, bound to the message
// id. Safe for concurrent use; one worker (Run) delivers.
type Queue struct {
	st         *store.Store
	box        *secret.Box
	sender     Sender
	log        *slog.Logger
	maxPerHour int
	now        func() time.Time
	wake       chan struct{}

	mu        sync.Mutex // serializes passes
	lastAlert time.Time
	lastPrune time.Time
}

// QueueOptions configure a queue.
type QueueOptions struct {
	// MaxPerHour is the global ceiling (mail.max_per_hour).
	MaxPerHour int
	Logger     *slog.Logger
	// Now replaces the clock (tests).
	Now func() time.Time
}

// NewQueue builds a queue over the store; box seals the content (the key
// of mfa.key_file); sender may be nil for a queue that only enqueues
// (another process delivers).
func NewQueue(st *store.Store, box *secret.Box, sender Sender, opt QueueOptions) *Queue {
	q := &Queue{st: st, box: box, sender: sender, log: opt.Logger, maxPerHour: opt.MaxPerHour, now: opt.Now,
		wake: make(chan struct{}, 1)}
	if q.log == nil {
		q.log = slog.Default()
	}
	if q.now == nil {
		q.now = time.Now
	}
	if q.maxPerHour < 1 {
		q.maxPerHour = 200
	}
	return q
}

var (
	kindRE      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	referenceRE = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{0,128}$`)
)

func aad(id string) []byte { return []byte("mail:" + id) }

// Enqueue stores a message for delivery and wakes the worker. expiresAt
// is when it stops being worth sending (the expiry of the link it
// carries; NotificationLifetime for a notification); reference is the
// caller's reference for the log (a token id, never personal data).
func (q *Queue) Enqueue(ctx context.Context, m Message, expiresAt time.Time, reference string) (string, error) {
	if !kindRE.MatchString(m.Kind) {
		return "", fmt.Errorf("mail: invalid kind %q", m.Kind)
	}
	if !referenceRE.MatchString(reference) {
		return "", errors.New("mail: invalid reference")
	}
	if _, err := ParseRecipient(m.To); err != nil {
		return "", err
	}
	if m.Subject == "" || m.Text == "" || m.HTML == "" {
		return "", errors.New("mail: subject and both bodies are required")
	}
	now := q.now().UTC()
	if !expiresAt.After(now) {
		return "", errors.New("mail: the message has already expired")
	}
	if expiresAt.Sub(now) > MaxLifetime {
		expiresAt = now.Add(MaxLifetime)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	r := store.MailRow{ID: id, Kind: m.Kind, Reference: reference, RecipientDomain: Domain(m.To), CreatedAt: now, NextAt: now, ExpiresAt: expiresAt.UTC()}
	for _, f := range []struct {
		dst *[]byte
		v   string
	}{{&r.RecipientSealed, m.To}, {&r.SubjectSealed, m.Subject}, {&r.TextSealed, m.Text}, {&r.HTMLSealed, m.HTML}} {
		sealed, err := q.box.Seal([]byte(f.v), aad(id))
		if err != nil {
			return "", err
		}
		*f.dst = sealed
	}
	if err := q.st.EnqueueMail(ctx, r); err != nil {
		return "", err
	}
	q.log.Info("mail queued", "id", id, "kind", m.Kind, "domain", r.RecipientDomain, "reference", reference)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return id, nil
}

// Stats counts the queue and the last 24 hours.
func (q *Queue) Stats(ctx context.Context) (store.MailStats, error) {
	return q.st.MailStats(ctx, q.now().Add(-24*time.Hour))
}

// Run delivers until ctx ends: at start, when a message is queued, every
// 30 seconds, and again right away after a full batch.
func (q *Queue) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		n, err := q.Process(ctx)
		if err != nil && ctx.Err() == nil {
			q.log.Error("mail queue", "err", err)
		}
		if err == nil && n == batch {
			// A full batch went out: more may be due right away (the
			// ceiling is checked again by the next pass).
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		case <-t.C:
		}
	}
}

// Process is one pass: expire what is past its time, then hand the due
// messages to the relay within the hourly ceiling. It returns how many
// were sent.
func (q *Queue) Process(ctx context.Context) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	expired, err := q.st.ExpiredMail(ctx, now)
	if err != nil {
		return 0, err
	}
	for _, r := range expired {
		if err := q.st.FinishMail(ctx, r.ID, store.MailExpired, r.Attempts, now, r.LastError); err != nil {
			return 0, err
		}
		q.log.Warn("mail expired before delivery", "id", r.ID, "attempts", r.Attempts, "last_error", r.LastError)
	}
	if now.Sub(q.lastPrune) > time.Hour {
		q.lastPrune = now
		if err := q.st.PruneMailLog(ctx, now.Add(-LogRetention)); err != nil {
			return 0, err
		}
	}
	if q.sender == nil {
		return 0, nil
	}
	sent, err := q.st.MailSentSince(ctx, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	budget := q.maxPerHour - sent
	if budget <= 0 {
		if pending, _ := q.st.DueMail(ctx, now, 1); len(pending) > 0 && now.Sub(q.lastAlert) >= alertEvery {
			q.lastAlert = now
			q.log.Warn("mail: hourly ceiling reached; messages wait in the queue", "max_per_hour", q.maxPerHour)
		}
		return 0, nil
	}
	due, err := q.st.DueMail(ctx, now, min(budget, batch))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range due {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		ok, err := q.deliver(ctx, r)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// deliver opens and sends one message and records the outcome; ok is
// true when the relay accepted it. The error is a store failure only.
func (q *Queue) deliver(ctx context.Context, r store.MailRow) (bool, error) {
	var m Message
	m.Kind = r.Kind
	for _, f := range []struct {
		dst    *string
		sealed []byte
	}{{&m.To, r.RecipientSealed}, {&m.Subject, r.SubjectSealed}, {&m.Text, r.TextSealed}, {&m.HTML, r.HTMLSealed}} {
		b, err := q.box.Open(f.sealed, aad(r.ID))
		if err != nil {
			// The state key changed or the row was tampered with: it can
			// never be sent.
			q.log.Error("mail cannot be decrypted; dropped", "id", r.ID, "kind", r.Kind)
			return false, q.st.FinishMail(ctx, r.ID, store.MailFailed, r.Attempts, q.now().UTC(), "cannot decrypt the queued message")
		}
		*f.dst = string(b)
	}
	attempts := r.Attempts + 1
	err := q.sender.Send(ctx, m)
	now := q.now().UTC()
	if err == nil {
		q.log.Info("mail sent", "id", r.ID, "kind", r.Kind, "attempts", attempts)
		return true, q.st.FinishMail(ctx, r.ID, store.MailSent, attempts, now, "")
	}
	msg := redact(err.Error())
	if errors.Is(err, ErrRecipientRefused) {
		q.log.Warn("mail refused by the relay; dropped", "id", r.ID, "kind", r.Kind, "err", msg)
		return false, q.st.FinishMail(ctx, r.ID, store.MailFailed, attempts, now, msg)
	}
	next := now.Add(backoff(attempts))
	q.log.Warn("mail delivery failed; will retry", "id", r.ID, "kind", r.Kind, "attempts", attempts, "next", next, "err", msg)
	return false, q.st.RetryMail(ctx, r.ID, attempts, next, now, msg)
}
