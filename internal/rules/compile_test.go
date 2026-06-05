package rules

import "testing"

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
}
