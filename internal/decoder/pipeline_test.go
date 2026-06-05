package decoder

import (
	"strings"
	"testing"
)

func TestMaxRecursionDepthIs3(t *testing.T) {
	if MaxRecursionDepth != 3 {
		t.Errorf("MaxRecursionDepth = %d, want 3", MaxRecursionDepth)
	}
}

func TestBase64UnpaddedDetected(t *testing.T) {
	in := "look at this: " + strings.Repeat("aGVsbG8h", 4) + " here"
	results := tryBase64(in)
	if len(results) == 0 {
		t.Errorf("base64 candidate not detected for unpadded string")
	}
}
