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
