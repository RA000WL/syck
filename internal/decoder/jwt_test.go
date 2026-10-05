package decoder

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
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

func TestTryJWTPaddedPayload(t *testing.T) {
	// Payload whose base64 form needs "=" padding, emitted padded.
	payload := base64.URLEncoding.EncodeToString([]byte(`{"sub":"123"}`))
	if !strings.HasSuffix(payload, "=") {
		t.Fatalf("test payload must be padded, got %q", payload)
	}
	token := "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig"
	results := tryJWT(token)
	if len(results) == 0 {
		t.Fatal("padded JWT should decode")
	}
	if !strings.Contains(results[0].Text, "sub") {
		t.Errorf("decoded JWT payload missing 'sub': %q", results[0].Text)
	}
}

func TestTryJWTUnpaddedPayload(t *testing.T) {
	// Same claims emitted unpadded (RFC 7519 style, len%4 != 0).
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"123"}`))
	if len(payload)%4 == 0 {
		t.Fatalf("test payload must need padding, got len %d", len(payload))
	}
	token := "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig"
	results := tryJWT(token)
	if len(results) == 0 {
		t.Fatal("unpadded JWT should decode")
	}
	if !strings.Contains(results[0].Text, "sub") {
		t.Errorf("decoded JWT payload missing 'sub': %q", results[0].Text)
	}
}

func TestIsJWTExpired_Expired(t *testing.T) {
	// exp: 1000000000 = 2001-09-09
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDAwMDB9.invalid"
	if !IsJWTExpired(token) {
		t.Error("expected JWT to be detected as expired")
	}
}

func TestIsJWTExpired_NotExpired(t *testing.T) {
	// exp: far future (2099)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDB9.invalid"
	if IsJWTExpired(token) {
		t.Error("expected JWT to NOT be expired")
	}
}

func TestIsJWTExpired_NoExp(t *testing.T) {
	// No exp claim
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.invalid"
	if IsJWTExpired(token) {
		t.Error("expected JWT without exp to NOT be detected as expired")
	}
}

func TestIsJWTExpired_RecentlyExpired(t *testing.T) {
	// exp: 1 second ago
	exp := time.Now().Unix() - 1
	payload := fmt.Sprintf(`{"exp":%d}`, exp)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	token := "eyJhbGciOiJIUzI1NiJ9." + encoded + ".sig"
	if !IsJWTExpired(token) {
		t.Error("expected recently expired JWT to be detected")
	}
}
