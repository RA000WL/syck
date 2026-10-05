package decoder

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestTryHexMixedCase(t *testing.T) {
	// hex.EncodeToString is all-lowercase, but real-world hex is often
	// mixed-case (e.g. an uppercase constant concatenated with a
	// lowercase-encoded value). Mixed-case hex must still decode.
	lower := hex.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE"))
	if len(tryHex("token="+lower)) == 0 {
		t.Fatal("lowercase hex should decode")
	}
	mixed := strings.ToUpper(lower[:8]) + lower[8:]
	results := tryHex("token=" + mixed)
	if len(results) == 0 {
		t.Fatal("mixed-case hex should decode")
	}
	if !strings.Contains(results[0].Text, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("decoded text = %q, want to contain %q", results[0].Text, "AKIAIOSFODNN7EXAMPLE")
	}
}

func TestTryHexNaturalWordNoFire(t *testing.T) {
	if len(tryHex("the beefcake face feeds deadbeef hunger")) != 0 {
		t.Fatal("natural words must not decode")
	}
}
