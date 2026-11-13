// Package ratelimit holds the in-memory limiters of sign-in, 2FA and
// password pages: a token bucket per client address and a failure counter
// per account.
//
// Memory is bounded: each limiter tracks at most maxKeys keys, and idle
// entries are pruned while the limiter is used (no goroutine). A limiter
// never drops a live entry to make room. When its table is full of live
// entries, every key it cannot track shares one overflow entry, so filling
// the table neither resets a tracked key nor gives new keys a free pass.
// The price is that, while the table stays full, keys that are not tracked
// yet are limited together; keeping it full takes maxKeys live entries,
// that is a sustained flood from many addresses.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// maxKeys bounds the entries of one limiter.
	maxKeys = 100_000
	// sweepInterval is how often idle entries are pruned during normal use.
	sweepInterval = time.Minute
	// fullSweepInterval bounds the extra sweeps of a full table, so a flood
	// of new keys cannot make every request walk the whole table.
	fullSweepInterval = time.Second
)

// AddrKey is the rate-limit key of a client address: the address itself
// for IPv4 (an IPv4-mapped IPv6 address is unmapped first) and its /64
// network for IPv6, as one host or site usually holds a whole /64. A value
// that is not an address is returned unchanged. Audit records keep the
// full address; only limiters use this key.
func AddrKey(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// Bucket allows Rate events per Per with bursts of Burst, per key.
type Bucket struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	keys  map[string]*bucketState
	// overflow is shared by the keys a full table cannot track.
	overflow  bucketState
	maxKeys   int
	lastSweep time.Time
	now       func() time.Time
}

type bucketState struct {
	tokens float64
	last   time.Time
}

// NewBucket returns a limiter of n events per period with burst n.
func NewBucket(n int, period time.Duration) *Bucket {
	return &Bucket{
		rate:     float64(n) / period.Seconds(),
		burst:    float64(n),
		keys:     map[string]*bucketState{},
		overflow: bucketState{tokens: float64(n)},
		maxKeys:  maxKeys,
		now:      time.Now,
	}
}

// Allow takes a token for key; false when the key is over its rate.
func (b *Bucket) Allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if now.Sub(b.lastSweep) >= sweepInterval {
		b.sweep(now)
	}
	st, ok := b.keys[key]
	if !ok {
		if len(b.keys) >= b.maxKeys && now.Sub(b.lastSweep) >= fullSweepInterval {
			b.sweep(now)
		}
		if len(b.keys) >= b.maxKeys {
			// Still full of live buckets: never reset one of them; the new
			// key shares the overflow bucket.
			st = &b.overflow
		} else {
			st = &bucketState{tokens: b.burst, last: now}
			b.keys[key] = st
		}
	}
	st.tokens = min(b.burst, st.tokens+max(0, now.Sub(st.last).Seconds())*b.rate)
	st.last = now
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

// sweep drops the buckets that refilled completely: forgetting them changes
// nothing, as a new bucket starts full.
func (b *Bucket) sweep(now time.Time) {
	for k, st := range b.keys {
		if st.tokens+now.Sub(st.last).Seconds()*b.rate >= b.burst {
			delete(b.keys, k)
		}
	}
	b.lastSweep = now
}

// Failures counts failed attempts per key in a sliding window.
type Failures struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	keys   map[string][]time.Time
	// overflow counts the failures of the keys a full table cannot track.
	overflow  []time.Time
	maxKeys   int
	lastSweep time.Time
	now       func() time.Time
}

// NewFailures blocks a key after max failures within window.
func NewFailures(maxFailures int, window time.Duration) *Failures {
	return &Failures{max: maxFailures, window: window, keys: map[string][]time.Time{}, maxKeys: maxKeys, now: time.Now}
}

// live drops the timestamps that left the window (oldest first).
func (f *Failures) live(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= f.window {
		i++
	}
	return ts[i:]
}

func (f *Failures) recent(key string, now time.Time) []time.Time {
	ts := f.live(f.keys[key], now)
	if len(ts) == 0 {
		delete(f.keys, key)
		return nil
	}
	f.keys[key] = ts
	return ts
}

// add appends a failure and keeps only the newest max timestamps: they
// alone decide whether the key is blocked, and they bound its memory.
func (f *Failures) add(ts []time.Time, now time.Time) []time.Time {
	ts = append(ts, now)
	if f.max > 0 && len(ts) > f.max {
		ts = ts[len(ts)-f.max:]
	}
	return ts
}

// sweep drops the keys whose newest failure left the window.
func (f *Failures) sweep(now time.Time) {
	for k, ts := range f.keys {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= f.window {
			delete(f.keys, k)
		}
	}
	f.lastSweep = now
}

func (f *Failures) maybeSweep(now time.Time) {
	if now.Sub(f.lastSweep) >= sweepInterval {
		f.sweep(now)
	}
}

// Blocked reports whether key reached the limit. A key the limiter does
// not track is judged by the overflow counter, which is empty unless the
// table filled up.
func (f *Failures) Blocked(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.maybeSweep(now)
	if ts := f.recent(key, now); ts != nil {
		return len(ts) >= f.max
	}
	f.overflow = f.live(f.overflow, now)
	return len(f.overflow) >= f.max
}

// Fail records a failure. It never forgets another key's failures: when the
// table is full of live keys, a new key's failure goes to the overflow
// counter shared by every untracked key.
func (f *Failures) Fail(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.maybeSweep(now)
	ts := f.recent(key, now)
	if ts == nil && len(f.keys) >= f.maxKeys {
		if now.Sub(f.lastSweep) >= fullSweepInterval {
			f.sweep(now)
		}
		if len(f.keys) >= f.maxKeys {
			f.overflow = f.add(f.live(f.overflow, now), now)
			return
		}
	}
	f.keys[key] = f.add(ts, now)
}

// Reset forgets a key (after a success).
func (f *Failures) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, key)
}

// SetClock replaces the clock of both limiters (tests).
func SetClock(now func() time.Time, b *Bucket, f *Failures) {
	if b != nil {
		b.now = now
	}
	if f != nil {
		f.now = now
	}
}
