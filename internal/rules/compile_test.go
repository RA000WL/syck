package rules

import (
	"sync"
	"testing"
)

func TestRuleCompilerCache(t *testing.T) {
	c := NewRuleCompiler()
	a, err := c.Compile("abc")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Compile("abc")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("expected same compiled regex from cache")
	}
	if _, err := c.Compile("[bad"); err == nil {
		t.Error("expected error for bad pattern")
	}
	if _, err := c.Compile("[bad"); err == nil {
		t.Error("expected error on second compile of bad pattern (negative caching)")
	}
}

func TestRuleCompilerConcurrent(t *testing.T) {
	c := NewRuleCompiler()
	primed, err := c.Compile("shared")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			re, err := c.Compile("shared")
			if err != nil {
				t.Error(err)
				return
			}
			if re != primed {
				t.Errorf("concurrent reader got different *regexp.Regexp than primed cache value")
			}
		}()
	}
	wg.Wait()
}
