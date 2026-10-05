package decoder

import (
	"bytes"
	"compress/gzip"
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

func TestTryGzipDecompressCapsOutput(t *testing.T) {
	// Highly compressible payload >5MB so the gzip input stays tiny.
	payload := bytes.Repeat([]byte("A"), 6<<20)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("writing gzip payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}

	out, ok := TryGzipDecompress(buf.Bytes())
	if !ok {
		t.Fatalf("TryGzipDecompress ok = false, want true")
	}
	if len(out) > 5<<20 {
		t.Errorf("len(out) = %d, want <= %d", len(out), 5<<20)
	}
	if len(out) == 0 {
		t.Errorf("len(out) = 0, want non-empty truncated output")
	}
}
