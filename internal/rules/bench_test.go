package rules

import (
	"testing"
)

func BenchmarkRuleMatchAll(b *testing.B) {
	rs, err := LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	rs.CompileAll()

	line := `const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"; // production key`
	for i := 0; i < b.N; i++ {
		for _, r := range rs.Rules {
			r.MatchAll(line)
		}
	}
}

func BenchmarkRuleMatchAll_NoMatch(b *testing.B) {
	rs, err := LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	rs.CompileAll()

	line := `function add(a, b) { return a + b; }`
	for i := 0; i < b.N; i++ {
		for _, r := range rs.Rules {
			r.MatchAll(line)
		}
	}
}

func BenchmarkRuleMatch_SingleRule(b *testing.B) {
	rs, err := LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	rs.CompileAll()

	line := `const key = "AKIAIOSFODNN7EXAMPLE"`
	// Find AWS rule
	for _, r := range rs.Rules {
		if r.Name == "aws_access_key_id" {
			for i := 0; i < b.N; i++ {
				r.MatchAll(line)
			}
			return
		}
	}
	b.Skip("aws_access_key_id rule not found")
}

func BenchmarkRuleCompile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rs, _ := LoadDefault()
		rs.CompileAll()
	}
}
