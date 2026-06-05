package decoder

import (
	"encoding/base64"
	"strings"
	"testing"
)

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestDoubleBase64Recurses(t *testing.T) {
	inner := strings.Repeat("x", 24) // 24 bytes -> base64 = 32 chars (no padding)
	once := base64Encode(inner)      // 32 chars, first-level base64
	twice := base64Encode(once)      // ~44 chars, second-level base64
	results := tryDoubleBase64(twice)
	if len(results) == 0 {
		t.Fatal("no double-base64 result")
	}
	// The decoded output should be the first-level base64 string (32+ chars of [A-Za-z0-9+/])
	if len(results[0].Text) < 32 {
		t.Errorf("decoded text too short: got %d chars, want >= 32", len(results[0].Text))
	}
}

func TestDoubleBase64CapAtDepth3(t *testing.T) {
	inner := strings.Repeat("x", 33) // 33 bytes -> base64 = 44 chars
	once := base64Encode(inner)
	twice := base64Encode(once)
	thrice := base64Encode(twice)
	results := tryDoubleBase64(thrice)
	if len(results) == 0 {
		t.Fatal("no result for 3-level nested string (still detectable)")
	}
}
