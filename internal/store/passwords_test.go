package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSettings(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if m, err := s.Settings(ctx); err != nil || len(m) != 0 {
		t.Fatalf("empty settings: %v %v", m, err)
	}
	if err := s.PutSettings(ctx, map[string]string{"reset.enabled": "true", "reset.minutes": "30"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSettings(ctx, map[string]string{"reset.minutes": "45"}, "other"); err != nil {
		t.Fatal(err)
	}
	m, err := s.Settings(ctx)
	if err != nil || m["reset.enabled"] != "true" || m["reset.minutes"] != "45" {
		t.Fatalf("%v %v", m, err)
	}
}

func TestRecoveryEmails(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const u = "S-1-5-21-1-2-3-1101"
	if _, err := s.GetRecoveryEmail(ctx, u); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	if err := s.SetRecoveryEmail(ctx, RecoveryEmail{UserSID: u, Address: "a@example.org", VerifiedAt: t0, ChangedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecoveryEmail(ctx, RecoveryEmail{UserSID: u, Address: "b@example.org", VerifiedAt: t0.Add(time.Hour), ChangedAt: t0.Add(time.Hour),
		PreviousNotified: true}); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetRecoveryEmail(ctx, u)
	if err != nil || r.Address != "b@example.org" || !r.ChangedAt.Equal(t0.Add(time.Hour)) || !r.PreviousNotified {
		t.Fatalf("%+v %v", r, err)
	}
	if err := s.DeleteRecoveryEmail(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRecoveryEmail(ctx, u); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestLinkTokens(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for i, p := range []string{"invite", "invite", "reset"} {
		tok := LinkToken{TokenID: string(rune('a'+i)) + "0000000000000000000000000000000", Purpose: p, UserSID: "S-1-5-21-1-2-3-1101",
			Username: "u", Lang: "en", IssuedAt: t0, ExpiresAt: t0.Add(time.Duration(i+1) * time.Hour)}
		if err := s.PutLinkToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetLinkToken(ctx, "a0000000000000000000000000000000")
	if err != nil || got.Purpose != "invite" || !got.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := s.GetLinkToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	exp, err := s.ExpiredInvites(ctx, t0.Add(150*time.Minute), 10)
	if err != nil || len(exp) != 2 {
		t.Fatalf("expired invites: %d %v", len(exp), err)
	}
	if err := s.MarkLinkTokenHandled(ctx, exp[0].TokenID); err != nil {
		t.Fatal(err)
	}
	if exp, _ = s.ExpiredInvites(ctx, t0.Add(150*time.Minute), 10); len(exp) != 1 {
		t.Fatalf("after handled: %d", len(exp))
	}
	if err := s.PruneLinkTokens(ctx, t0.Add(10*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// The handled invite and the reset are gone; the unhandled invite stays.
	if _, err := s.GetLinkToken(ctx, "a0000000000000000000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatal("handled invite kept")
	}
	if _, err := s.GetLinkToken(ctx, "b0000000000000000000000000000000"); err != nil {
		t.Fatal("unhandled invite pruned")
	}
}
