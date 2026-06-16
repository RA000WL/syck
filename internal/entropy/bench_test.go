package entropy

import "testing"

func BenchmarkShannon_ShortASCII(b *testing.B) {
	data := "AKIAIOSFODNN7EXAMPLE"
	for i := 0; i < b.N; i++ {
		Shannon(data)
	}
}

func BenchmarkShannon_LongASCII(b *testing.B) {
	data := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	for i := 0; i < b.N; i++ {
		Shannon(data)
	}
}

func BenchmarkShannon_NonASCII(b *testing.B) {
	data := "Héllo Wörld — tëst dâta with ünicôde chars 日本語テスト"
	for i := 0; i < b.N; i++ {
		Shannon(data)
	}
}

func BenchmarkShannon_Empty(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Shannon("")
	}
}

func BenchmarkHasSecretContext(b *testing.B) {
	line := `const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"; // TODO: move to env var`
	for i := 0; i < b.N; i++ {
		HasSecretContext(line)
	}
}

func BenchmarkHasSecretContext_NoMatch(b *testing.B) {
	line := `function add(a, b) { return a + b; }`
	for i := 0; i < b.N; i++ {
		HasSecretContext(line)
	}
}

func BenchmarkEntropyTokenRe(b *testing.B) {
	line := `const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	for i := 0; i < b.N; i++ {
		EntropyTokenRe.FindAllString(line, -1)
	}
}
