package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func mailRow(id string, at time.Time) MailRow {
	return MailRow{ID: id, Kind: "test", RecipientSealed: []byte("r"), SubjectSealed: []byte("s"), TextSealed: []byte("t"),
		HTMLSealed: []byte("h"), Reference: "ref-" + id, RecipientDomain: "example.org", CreatedAt: at, NextAt: at, ExpiresAt: at.Add(time.Hour)}
}

func TestMailQueueAndLog(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c"} {
		if err := s.EnqueueMail(ctx, mailRow(id, t0.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.EnqueueMail(ctx, mailRow("a", t0)); err == nil {
		t.Fatal("duplicate id accepted")
	}
	due, err := s.DueMail(ctx, t0.Add(90*time.Second), 10)
	if err != nil || len(due) != 2 || due[0].ID != "a" || due[1].ID != "b" {
		t.Fatalf("due %v %+v", err, due)
	}
	if string(due[0].TextSealed) != "t" || due[0].Reference != "ref-a" || !due[0].ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("row %+v", due[0])
	}
	if due, _ := s.DueMail(ctx, t0.Add(time.Hour), 1); len(due) != 1 {
		t.Fatal("limit")
	}

	// A failed attempt moves next_at and records the error in both tables.
	if err := s.RetryMail(ctx, "a", 1, t0.Add(10*time.Minute), t0, "451 later"); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.DueMail(ctx, t0.Add(5*time.Minute), 10); len(due) != 2 || due[0].ID != "b" {
		t.Fatalf("after retry %+v", due)
	}
	lr, err := s.GetMailLog(ctx, "a")
	if err != nil || lr.Status != MailRetrying || lr.Attempts != 1 || lr.Error != "451 later" || lr.RecipientDomain != "example.org" {
		t.Fatalf("log %+v %v", lr, err)
	}
	st, err := s.MailStats(ctx, t0.Add(-time.Hour))
	if err != nil || st.Pending != 3 || st.Retrying != 1 || st.Sent != 0 {
		t.Fatalf("stats %+v %v", st, err)
	}

	// Finishing deletes the queued content and records the outcome.
	if err := s.FinishMail(ctx, "b", MailSent, 1, t0.Add(2*time.Minute), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishMail(ctx, "c", MailFailed, 1, t0.Add(3*time.Minute), "550 no such user"); err != nil {
		t.Fatal(err)
	}
	lr, _ = s.GetMailLog(ctx, "b")
	if lr.Status != MailSent || !lr.SentAt.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("sent log %+v", lr)
	}
	if lr, _ := s.GetMailLog(ctx, "c"); lr.Status != MailFailed || !lr.SentAt.IsZero() {
		t.Fatalf("failed log %+v", lr)
	}
	if due, _ := s.DueMail(ctx, t0.Add(time.Hour), 10); len(due) != 1 || due[0].ID != "a" {
		t.Fatalf("queue after finishing %+v", due)
	}
	if n, _ := s.MailSentSince(ctx, t0); n != 1 {
		t.Fatalf("sent since %d", n)
	}
	if n, _ := s.MailSentSince(ctx, t0.Add(3*time.Minute)); n != 0 {
		t.Fatalf("sent since later %d", n)
	}
	st, _ = s.MailStats(ctx, t0.Add(-time.Hour))
	if st.Pending != 1 || st.Sent != 1 || st.Failed != 1 {
		t.Fatalf("stats %+v", st)
	}

	// Expiry: past expires_at.
	exp, err := s.ExpiredMail(ctx, t0.Add(time.Hour))
	if err != nil || len(exp) != 1 || exp[0].ID != "a" || exp[0].Attempts != 1 || exp[0].LastError != "451 later" {
		t.Fatalf("expired %+v %v", exp, err)
	}
	if exp, _ := s.ExpiredMail(ctx, t0.Add(59*time.Minute)); len(exp) != 0 {
		t.Fatal("not yet expired")
	}

	// The log, newest first; the log table has no recipient or content.
	rows, err := s.MailLog(ctx, 10)
	if err != nil || len(rows) != 3 || rows[0].ID != "c" {
		t.Fatalf("log %+v %v", rows, err)
	}
	var cols []string
	r, err := s.db.QueryContext(ctx, `SELECT name FROM pragma_table_info('mail_log')`)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var c string
		_ = r.Scan(&c)
		cols = append(cols, c)
	}
	_ = r.Close()
	for _, c := range cols {
		if (strings.Contains(c, "recipient") && c != "recipient_domain") || strings.Contains(c, "body") || strings.Contains(c, "subject") {
			t.Fatalf("mail_log column %q", c)
		}
	}

	// Pruning keeps rows of messages still queued.
	if err := s.PruneMailLog(ctx, t0.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMailLog(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old log row kept")
	}
	if _, err := s.GetMailLog(ctx, "a"); err != nil {
		t.Fatal("log row of a queued message pruned")
	}
}
