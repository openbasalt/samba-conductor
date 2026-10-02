package ratelimit

import (
	"testing"
	"time"
)

func TestBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBucket(3, time.Minute)
	SetClock(func() time.Time { return now }, b, nil)
	for i := range 3 {
		if !b.Allow("1.2.3.4") {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if b.Allow("1.2.3.4") {
		t.Fatal("4th attempt in the same instant allowed")
	}
	if !b.Allow("5.6.7.8") {
		t.Fatal("another address refused")
	}
	now = now.Add(20 * time.Second) // one token back
	if !b.Allow("1.2.3.4") || b.Allow("1.2.3.4") {
		t.Fatal("refill")
	}
}

func TestFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailures(2, 10*time.Minute)
	SetClock(func() time.Time { return now }, nil, f)
	f.Fail("alice")
	if f.Blocked("alice") {
		t.Fatal("blocked after one failure")
	}
	f.Fail("alice")
	if !f.Blocked("alice") || f.Blocked("bob") {
		t.Fatal("block")
	}
	now = now.Add(11 * time.Minute)
	if f.Blocked("alice") {
		t.Fatal("window did not slide")
	}
	f.Fail("alice")
	f.Reset("alice")
	f.Fail("alice")
	if f.Blocked("alice") {
		t.Fatal("reset ignored")
	}
}
