package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/rules"
)

func BenchmarkScanLineForRegexRules(b *testing.B) {
	rs, err := rules.LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	cfg := Config{Rules: rs}
	lines := []string{
		`const api_key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12";`,
		`  let total = invoice.subtotal + invoice.tax;`,
		`<script src="https://cdn.example.com/app.js"></script>`,
		`aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
		`const res = await fetch('/api/v1/users?id=42');`,
		`// TODO: refactor this legacy path before Q4 release`,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanLineForRegexRules(lines[i%len(lines)], i+1, "app.js", cfg, "", nil)
	}
}
