package decoder

import "testing"

func BenchmarkTryBase64(b *testing.B) {
	line := `const secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	for i := 0; i < b.N; i++ {
		tryBase64(line)
	}
}

func BenchmarkTryHex(b *testing.B) {
	line := `const key = "48656c6c6f20576f726c6420415049204b65792031323334353637383930"`
	for i := 0; i < b.N; i++ {
		tryHex(line)
	}
}

func BenchmarkTryUnicodeEscapes(b *testing.B) {
	line := `var x = "\u0048\u0065\u006c\u006c\u006f\u0020\u0057\u006f\u0072\u006c\u0064"`
	for i := 0; i < b.N; i++ {
		tryUnicodeEscapes(line)
	}
}

func BenchmarkTryURLEncoded(b *testing.B) {
	line := `url = "https://example.com/path%20with%20spaces?key=value%26other=test"`
	for i := 0; i < b.N; i++ {
		tryURLEncoded(line)
	}
}

func BenchmarkDecodeAndRescan(b *testing.B) {
	// This would need rules to be loaded — skip for now
	// Just benchmark the decoder selection
	line := `const encoded = "SGVsbG8gV29ybGQ="`
	flags := Flags{Base64: true}
	decoders := defaultRegistry.Active(flags)
	for i := 0; i < b.N; i++ {
		for _, dec := range decoders {
			dec(line)
		}
	}
}
