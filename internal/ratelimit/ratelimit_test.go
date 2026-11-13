package ratelimit

import (
	"fmt"
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

// Filling the table with failures for other keys must never reset the
// counter of a key that is already blocked.
func TestFailuresFullTableKeepsCounters(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailures(3, 15*time.Minute)
	f.maxKeys = 100
	SetClock(func() time.Time { return now }, nil, f)
	for range 3 {
		f.Fail("victim")
	}
	if !f.Blocked("victim") {
		t.Fatal("victim not blocked")
	}
	for i := range 10 * f.maxKeys {
		f.Fail(fmt.Sprintf("junk%d", i))
		if i%50 == 0 {
			now = now.Add(time.Second)
		}
	}
	if !f.Blocked("victim") {
		t.Fatal("victim's counter was reset by unrelated failures")
	}
	if len(f.keys) > f.maxKeys {
		t.Fatalf("table grew past its bound: %d", len(f.keys))
	}
}

// A key the full table cannot track shares the overflow counter: untracked
// keys together get no more than max failures per window, and a tracked
// key keeps its own count.
func TestFailuresOverflow(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailures(3, 15*time.Minute)
	f.maxKeys = 10
	SetClock(func() time.Time { return now }, nil, f)
	f.Fail("tracked")
	for i := range f.maxKeys - 1 {
		f.Fail(fmt.Sprintf("junk%d", i))
	}
	if len(f.keys) != f.maxKeys {
		t.Fatalf("table not full: %d", len(f.keys))
	}
	// Normal operation: an untracked key that never failed is free.
	if f.Blocked("victim") {
		t.Fatal("untracked key blocked while the overflow is empty")
	}
	for range 3 {
		if f.Blocked("victim") {
			t.Fatal("victim blocked too early")
		}
		f.Fail("victim")
	}
	if _, ok := f.keys["victim"]; ok {
		t.Fatal("full table tracked a new key")
	}
	if !f.Blocked("victim") || !f.Blocked("someone.else") {
		t.Fatal("overflow did not limit untracked keys")
	}
	// Tracked keys are not affected by the overflow.
	if f.Blocked("tracked") {
		t.Fatal("tracked key blocked by the overflow")
	}
	f.Fail("tracked")
	f.Fail("tracked")
	if !f.Blocked("tracked") {
		t.Fatal("tracked key lost its count")
	}
	// The overflow slides like any other key.
	now = now.Add(16 * time.Minute)
	if f.Blocked("victim") {
		t.Fatal("overflow window did not slide")
	}
}

// Expired keys are pruned as the limiter is used, without a goroutine, and
// a full table makes room by dropping expired keys only.
func TestFailuresPrune(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailures(3, 15*time.Minute)
	f.maxKeys = 100
	SetClock(func() time.Time { return now }, nil, f)
	for i := range 50 {
		f.Fail(fmt.Sprintf("old%d", i))
	}
	now = now.Add(10 * time.Minute)
	for range 3 {
		f.Fail("victim")
	}
	// After the old keys expired, any use of the limiter prunes them.
	now = now.Add(6 * time.Minute)
	f.Blocked("unrelated")
	if len(f.keys) != 1 {
		t.Fatalf("expired keys not pruned: %d left", len(f.keys))
	}
	if !f.Blocked("victim") {
		t.Fatal("pruning dropped a live key")
	}

	// Full table: the next new key reclaims expired slots and is tracked.
	g := NewFailures(3, 15*time.Minute)
	g.maxKeys = 10
	SetClock(func() time.Time { return now }, nil, g)
	for i := range g.maxKeys {
		g.Fail(fmt.Sprintf("old%d", i))
	}
	now = now.Add(16 * time.Minute)
	// The routine sweep ran recently, so only the full-table one applies.
	g.lastSweep = now.Add(-2 * time.Second)
	g.Fail("new")
	if _, ok := g.keys["new"]; !ok || len(g.keys) != 1 {
		t.Fatalf("full table did not reclaim expired keys: %d keys", len(g.keys))
	}
}

// One key keeps at most max timestamps, however many failures it gets.
func TestFailuresPerKeyBound(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFailures(5, time.Hour)
	SetClock(func() time.Time { return now }, nil, f)
	for range 1000 {
		f.Fail("alice")
		now = now.Add(time.Millisecond)
	}
	if n := len(f.keys["alice"]); n != 5 {
		t.Fatalf("alice holds %d timestamps", n)
	}
	if !f.Blocked("alice") {
		t.Fatal("alice not blocked")
	}
}

// A full bucket table never drops live buckets: a new key shares the
// overflow bucket instead of resetting an exhausted one.
func TestBucketFullTable(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBucket(2, time.Minute)
	b.maxKeys = 10
	SetClock(func() time.Time { return now }, b, nil)
	b.Allow("attacker")
	b.Allow("attacker")
	if b.Allow("attacker") {
		t.Fatal("attacker not limited")
	}
	for i := range 100 {
		b.Allow(fmt.Sprintf("junk%d", i))
	}
	if len(b.keys) > b.maxKeys {
		t.Fatalf("table grew past its bound: %d", len(b.keys))
	}
	if b.Allow("attacker") {
		t.Fatal("attacker's bucket was reset by a full table")
	}
	// The junk keys exhausted the shared overflow bucket.
	if b.Allow("newcomer") {
		t.Fatal("overflow bucket not shared")
	}
	// Once buckets refill they are pruned and new keys are tracked again.
	now = now.Add(2 * time.Minute)
	if !b.Allow("newcomer") {
		t.Fatal("newcomer refused after the table drained")
	}
	if _, ok := b.keys["newcomer"]; !ok {
		t.Fatal("newcomer not tracked after the prune")
	}
}

func TestAddrKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.10":                "192.0.2.10",
		"::ffff:192.0.2.10":         "192.0.2.10",
		"2001:db8:1:2:3:4:5:6":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1":      "2001:db8:1:2::/64",
		"2001:db8:1:3::1":           "2001:db8:1:3::/64",
		"fe80::1%eth0":              "fe80::/64",
		"::1":                       "::/64",
		"not-an-address":            "not-an-address",
		"2001:db8::1:2:3:4:5:6:7:8": "2001:db8::1:2:3:4:5:6:7:8",
	} {
		if got := AddrKey(in); got != want {
			t.Errorf("AddrKey(%q) = %q, want %q", in, got, want)
		}
	}
	// Two addresses of one /64 share a bucket; another /64 does not.
	b := NewBucket(1, time.Minute)
	if !b.Allow(AddrKey("2001:db8:1:2::a")) || b.Allow(AddrKey("2001:db8:1:2::b")) {
		t.Fatal("addresses of one /64 do not share a bucket")
	}
	if !b.Allow(AddrKey("2001:db8:1:3::a")) {
		t.Fatal("another /64 shares the bucket")
	}
	if !b.Allow(AddrKey("192.0.2.1")) || !b.Allow(AddrKey("192.0.2.2")) {
		t.Fatal("IPv4 addresses share a bucket")
	}
}
