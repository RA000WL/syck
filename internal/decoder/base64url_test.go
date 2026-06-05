package decoder

import (
	"strings"
	"testing"
)

func TestBase64URLDecode(t *testing.T) {
	in := "prefix " + strings.Repeat("aGVsbG8-", 4) + " suffix"
	results := tryBase64URL(in)
	if len(results) == 0 {
		t.Fatal("no base64url result produced")
	}
	if !strings.HasPrefix(results[0].Text, "hello") {
		t.Errorf("decoded text = %q, want prefix 'hello'", results[0].Text)
	}
}

func TestBase64URLWithUnderscore(t *testing.T) {
	in := "value: " + strings.Repeat("aGVsbG8_", 4) + " end"
	results := tryBase64URL(in)
	if len(results) == 0 {
		t.Fatal("no base64url result for underscore variant")
	}
}
