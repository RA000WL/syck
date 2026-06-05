package decoder

import (
	"strings"
	"testing"
)

func TestJWTDecodePayload(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJBbGljZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	results := tryJWT(jwt)
	if len(results) == 0 {
		t.Fatal("no JWT result produced")
	}
	if !strings.Contains(results[0].Text, "Alice") {
		t.Errorf("decoded JWT payload missing 'Alice': %q", results[0].Text)
	}
}

func TestJWTRejectNonJWT(t *testing.T) {
	results := tryJWT("not.a.jwt.really")
	if len(results) != 0 {
		t.Errorf("non-JWT string produced %d results, want 0", len(results))
	}
}
