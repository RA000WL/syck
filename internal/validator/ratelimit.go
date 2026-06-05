package validator

import (
	"sync"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mu    sync.Mutex
	rates map[string]*rate.Limiter
	rps   float64
}

func NewRateLimiter(rps float64) *RateLimiter {
	return &RateLimiter{
		rates: make(map[string]*rate.Limiter),
		rps:   rps,
	}
}

func (rl *RateLimiter) Allow(host string) bool {
	rl.mu.Lock()
	lim, ok := rl.rates[host]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(rl.rps), 1)
		rl.rates[host] = lim
	}
	rl.mu.Unlock()
	return lim.Allow()
}

func (rl *RateLimiter) SetRate(rps float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rps = rps
	for _, lim := range rl.rates {
		lim.SetLimit(rate.Limit(rps))
	}
}

func SetRate(rps float64) {
	defaultRateLimiter.SetRate(rps)
}
