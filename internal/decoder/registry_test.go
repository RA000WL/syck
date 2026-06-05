package decoder

import (
	"sync"
	"testing"
)

func TestRegistryRegisterAndActive(t *testing.T) {
	r := NewRegistry()
	called := 0
	mu := sync.Mutex{}
	r.Register("test", func(s string) []DecodeResult {
		mu.Lock()
		called++
		mu.Unlock()
		return nil
	})
	results := r.Active(Flags{Base64: false})
	if len(results) != 1 {
		t.Errorf("Active returned %d, want 1", len(results))
	}
	results[0]("test input")
	if called != 1 {
		t.Errorf("Decode called %d times, want 1", called)
	}
}

func TestRegistryConcurrentSafe(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.Register("foo", func(s string) []DecodeResult { return nil })
		}()
		go func() {
			defer wg.Done()
			_ = r.Active(Flags{Base64: true})
		}()
	}
	wg.Wait()
}
