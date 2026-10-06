package crawler

import (
	"sync"
	"testing"
	"time"
)

// rps=5 => minGap = 200ms. A wait that is inside its sleep must not block
// an unrelated host's wait, otherwise --rate-limit N collapses from
// "N requests/sec per host" into "N requests/sec across the whole crawl".
const testRPS = 5

// TestRateLimiterSleepsOutsideLock is the core pin for this fix: while one
// host is inside its minGap sleep, a wait on a *different* host must return
// immediately instead of queueing on the mutex that the sleeper holds.
//
// Discrimination (this is the assertion that fails before the fix):
//   - before: hostRateLimiter.Wait held h.mu across time.Sleep, so the probe
//     below blocked on h.mu.Lock() for the remainder of the sleeper's ~200ms.
//   - after: the sleep happens with h.mu released, so the probe costs ~0.
//
// The threshold (100ms against a 200ms minGap) sits far from both outcomes,
// so this measures lock scope rather than scheduler jitter and stays reliable
// under -race. The probe sleeps 20ms first to guarantee the other goroutine
// is already inside its sleep.
func TestRateLimiterSleepsOutsideLock(t *testing.T) {
	rl := newHostRateLimiter(testRPS)
	if rl == nil {
		t.Fatal("newHostRateLimiter(5) = nil, want a limiter")
	}
	if rl.minGap != 200*time.Millisecond {
		t.Fatalf("minGap = %v, want %v", rl.minGap, 200*time.Millisecond)
	}

	// Prime the sleeper's host so its next wait actually sleeps for minGap.
	rl.Wait("slow.example.test")

	done := make(chan struct{})
	go func() {
		defer close(done)
		rl.Wait("slow.example.test") // ~200ms sleep, holding h.mu if broken
	}()

	time.Sleep(20 * time.Millisecond) // let the goroutine enter its sleep

	// A never-seen host has nothing to wait for and must return at once.
	start := time.Now()
	rl.Wait("fresh.example.test")
	elapsed := time.Since(start)

	<-done

	if elapsed >= 100*time.Millisecond {
		t.Errorf("wait on an unrelated host blocked %v while another host was in its minGap sleep; "+
			"want < 100ms (the sleep must happen outside h.mu)", elapsed)
	}
}

// TestRateLimiterAllowsPerHostOverlap pins the end-to-end shape the fix is
// for: three hosts, each already served once, waited on concurrently must
// overlap (~one minGap total) rather than stack (~three minGap). A regression
// to a single global timestamp, or to dropping the sleep entirely, fails here.
func TestRateLimiterAllowsPerHostOverlap(t *testing.T) {
	rl := newHostRateLimiter(testRPS)
	if rl == nil {
		t.Fatal("newHostRateLimiter(5) = nil, want a limiter")
	}

	names := []string{"a.example.test", "b.example.test", "c.example.test"}
	for _, host := range names {
		rl.Wait(host) // prime; an unprimed host returns instantly and proves nothing
	}

	var wg sync.WaitGroup
	start := time.Now()
	for _, host := range names {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			rl.Wait(h)
		}(host)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Overlapped: ~200ms. Serialized or globally rate limited: ~600ms.
	if elapsed >= 350*time.Millisecond {
		t.Errorf("3 hosts waited %v; want < 350ms (per-host waits must overlap, not share one minGap)", elapsed)
	}
	// Guards against a fix that "overlaps" by never sleeping at all.
	if elapsed < 100*time.Millisecond {
		t.Errorf("3 hosts waited %v; want >= 100ms (minGap was not enforced)", elapsed)
	}
}

// TestRateLimiterSameHostRespectsGap is the other half of the per-host
// contract: with the mutex released for the sleep, a repeat wait on the SAME
// host must still be held off by minGap. Without this, "sleep outside the
// lock" could regress into "no longer rate limited".
func TestRateLimiterSameHostRespectsGap(t *testing.T) {
	rl := newHostRateLimiter(testRPS)
	if rl == nil {
		t.Fatal("newHostRateLimiter(5) = nil, want a limiter")
	}

	rl.Wait("solo.example.test")

	start := time.Now()
	rl.Wait("solo.example.test")
	elapsed := time.Since(start)

	// A skipped wait (nil limiter, dropped sleep, timestamp never written)
	// shows up here as a near-instant second wait.
	if elapsed < rl.minGap {
		t.Errorf("repeat wait on the same host took %v; want >= minGap %v", elapsed, rl.minGap)
	}
}

// TestRateLimiterNilIsNoOp guards the rps<=0 construction path, which the
// crawl loop relies on: c.rateLim is nil whenever --rate-limit is unset.
func TestRateLimiterNilIsNoOp(t *testing.T) {
	var rl *hostRateLimiter
	rl.Wait("any.example.test") // must not panic
}
