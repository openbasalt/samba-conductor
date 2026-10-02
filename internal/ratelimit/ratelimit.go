// Package ratelimit holds the in-memory limiters of sign-in, 2FA and
// password pages: a token bucket per client address and a failure counter
// per account.
package ratelimit

import (
	"sync"
	"time"
)

// maxKeys bounds memory; when reached, the oldest-idle entries go first.
const maxKeys = 100_000

// Bucket allows Rate events per Per with bursts of Burst, per key.
type Bucket struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	keys  map[string]*bucketState
	now   func() time.Time
}

type bucketState struct {
	tokens float64
	last   time.Time
}

// NewBucket returns a limiter of n events per period with burst n.
func NewBucket(n int, period time.Duration) *Bucket {
	return &Bucket{rate: float64(n) / period.Seconds(), burst: float64(n), keys: map[string]*bucketState{}, now: time.Now}
}

// Allow takes a token for key; false when the key is over its rate.
func (b *Bucket) Allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	st, ok := b.keys[key]
	if !ok {
		if len(b.keys) >= maxKeys {
			b.evict(now)
		}
		st = &bucketState{tokens: b.burst, last: now}
		b.keys[key] = st
	}
	st.tokens = min(b.burst, st.tokens+now.Sub(st.last).Seconds()*b.rate)
	st.last = now
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

func (b *Bucket) evict(now time.Time) {
	for k, st := range b.keys {
		if st.tokens+now.Sub(st.last).Seconds()*b.rate >= b.burst {
			delete(b.keys, k)
		}
	}
	if len(b.keys) >= maxKeys {
		// Still full: drop everything rather than grow without bound.
		clear(b.keys)
	}
}

// Failures counts failed attempts per key in a sliding window.
type Failures struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	keys   map[string][]time.Time
	now    func() time.Time
}

// NewFailures blocks a key after max failures within window.
func NewFailures(maxFailures int, window time.Duration) *Failures {
	return &Failures{max: maxFailures, window: window, keys: map[string][]time.Time{}, now: time.Now}
}

func (f *Failures) recent(key string, now time.Time) []time.Time {
	ts := f.keys[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= f.window {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(f.keys, key)
		return nil
	}
	f.keys[key] = ts
	return ts
}

// Blocked reports whether key reached the limit.
func (f *Failures) Blocked(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recent(key, f.now())) >= f.max
}

// Fail records a failure.
func (f *Failures) Fail(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	ts := f.recent(key, now)
	if len(f.keys) >= maxKeys {
		clear(f.keys)
	}
	f.keys[key] = append(ts, now)
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
