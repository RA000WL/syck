package entropy

import (
	"math"
	"testing"
)

func TestBase64Entropy(t *testing.T) {
	if got := Base64Entropy("a"); math.Abs(got-0) > 0.01 {
		t.Errorf("Base64Entropy(\"a\") = %v, want 0", got)
	}
	if got := Base64Entropy("ab"); math.Abs(got-1.0) > 0.01 {
		t.Errorf("Base64Entropy(\"ab\") = %v, want 1.0", got)
	}
	if got := Base64Entropy("aGVsbG8="); got < 2.0 {
		t.Errorf("Base64Entropy(\"aGVsbG8=\") = %v, want >= 2.0", got)
	}
}

func TestHexEntropy(t *testing.T) {
	if got := HexEntropy("01"); math.Abs(got-1.0) > 0.01 {
		t.Errorf("HexEntropy(\"01\") = %v, want 1.0", got)
	}
	if got := HexEntropy("deadbeef"); got < 2.0 {
		t.Errorf("HexEntropy(\"deadbeef\") = %v, want >= 2.0", got)
	}
}

func TestJwtEntropy(t *testing.T) {
	if got := JwtEntropy("--"); math.Abs(got-0) > 0.01 {
		t.Errorf("JwtEntropy(\"--\") = %v, want 0", got)
	}
	if got := JwtEntropy("aGVsbG8_aGVsbG8"); got < 2.5 {
		t.Errorf("JwtEntropy(\"aGVsbG8_aGVsbG8\") = %v, want >= 2.5", got)
	}
}

func TestIsMediaTokenPNG(t *testing.T) {
	tok := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	if !IsMediaToken(tok) {
		t.Error("expected PNG to be detected as media")
	}
}

func TestIsMediaTokenJPEG(t *testing.T) {
	tok := "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYI5SDFUJRVxQyMkJzNictI2QwM0YzNERmcVJjVUdjhKS09SVGFhcZGlcYW5jZSUISYoM0NUV1JjZGVjZGVoYmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9sAQwAaGhopHSlBJiZBQi8vL0JHPz4+P0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dH/9sAQwEaKSk0JjQ/KCg/Rz81P0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHRf/dAAQAAf/aAAwDAQACEQMRAD8A"
	if !IsMediaToken(tok) {
		t.Error("expected JPEG to be detected as media")
	}
}

func TestIsMediaTokenGIF(t *testing.T) {
	tok := "R0lGODdhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs="
	if !IsMediaToken(tok) {
		t.Error("expected GIF to be detected as media")
	}
}

func TestIsMediaTokenSVG(t *testing.T) {
	tok := "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg=="
	if !IsMediaToken(tok) {
		t.Error("expected SVG to be detected as media")
	}
}

func TestIsMediaTokenWebP(t *testing.T) {
	tok := "UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERAPAP4A"
	if !IsMediaToken(tok) {
		t.Error("expected WebP to be detected as media")
	}
}

func TestIsMediaTokenNonWebPRIFF(t *testing.T) {
	// WAV shares RIFF header but is not a WebP; should NOT be detected
	tok := "UklGRgAAAABXQVZF"
	if IsMediaToken(tok) {
		t.Error("expected WAV (non-WebP RIFF) to NOT be detected as media")
	}
}

func TestIsMediaTokenWOFF(t *testing.T) {
	tok := "d09GRgABAAAAAACwAAAAAAADAAgA"
	if !IsMediaToken(tok) {
		t.Error("expected WOFF to be detected as media")
	}
}

func TestIsMediaTokenWOFF2(t *testing.T) {
	tok := "d09GMgABAAAAAACwAAAAAAADAAgA"
	if !IsMediaToken(tok) {
		t.Error("expected WOFF2 to be detected as media")
	}
}

func TestIsMediaTokenTTF(t *testing.T) {
	tok := "AAEAAAABAQA"
	if !IsMediaToken(tok) {
		t.Error("expected TTF to be detected as media")
	}
}

func TestIsMediaTokenOTF(t *testing.T) {
	tok := "T1RUTwABAAAA"
	if !IsMediaToken(tok) {
		t.Error("expected OTF to be detected as media")
	}
}

func TestIsMediaTokenXML(t *testing.T) {
	tok := "PD94bWw="
	if !IsMediaToken(tok) {
		t.Error("expected XML to be detected as media")
	}
}

func TestIsMediaTokenICO(t *testing.T) {
	tok := "AAABAA=="
	if !IsMediaToken(tok) {
		t.Error("expected ICO to be detected as media")
	}
}

func TestIsMediaTokenTIFFLE(t *testing.T) {
	tok := "SUkqAA=="
	if !IsMediaToken(tok) {
		t.Error("expected TIFF LE to be detected as media")
	}
}

func TestIsMediaTokenTIFFBE(t *testing.T) {
	tok := "TU0AKg=="
	if !IsMediaToken(tok) {
		t.Error("expected TIFF BE to be detected as media")
	}
}

func TestIsMediaTokenBMP(t *testing.T) {
	tok := "Qk0AAA=="
	if !IsMediaToken(tok) {
		t.Error("expected BMP to be detected as media")
	}
}

func TestIsMediaTokenRandomString(t *testing.T) {
	tokens := []string{
		"sk_live_abcdefghijklmnopqrstuvwxyz123456",
		"ghp_abcdefghijklmnopqrstuvwxyz1234567890",
		"AKIAIOSFODNN7EXAMPLE1234567890",
	}
	for _, tok := range tokens {
		if IsMediaToken(tok) {
			t.Errorf("expected %q to NOT be detected as media", tok)
		}
	}
}

func TestIsMediaTokenInvalidBase64(t *testing.T) {
	tok := "!!!not-base64!!!"
	if IsMediaToken(tok) {
		t.Error("expected invalid base64 to NOT be detected as media")
	}
}

func TestIsMediaTokenShortString(t *testing.T) {
	tok := "abc"
	if IsMediaToken(tok) {
		t.Error("expected short string to NOT be detected as media")
	}
}

func TestIsEntropyTokenMatchUsesAlphabet(t *testing.T) {
	hex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !IsEntropyTokenMatch(hex) {
		t.Error("expected 16-unique-char lowercase hex token to match")
	}
	b64 := "abcdefghijklmnopqrstuvwxyz+/0123"
	if !IsEntropyTokenMatch(b64) {
		t.Error("expected high-entropy base64 token to match")
	}
	lowHex := "0000000000000000000000000000000000000000000000000000000000000000"
	if IsEntropyTokenMatch(lowHex) {
		t.Error("expected all-zero hex token to be rejected (entropy=0, below hex threshold)")
	}
}
