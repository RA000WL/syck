package decoder

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

const lateSecretAWSRule = `\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`

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

func TestDecodedScanSeesLateSecret(t *testing.T) {
	// AWS-style secret placed at offset >500 inside the base64-decoded blob —
	// past the old 500-char truncation point of scanDecodedChunk. The space
	// keeps the word boundary before the key intact.
	secret := "AKIAIOSFODNN7EXAMPLE"
	payload := strings.Repeat("A", 600) + " " + secret
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	line := `const blob = "` + encoded + `"`

	rs := &rules.RuleSet{
		Rules: []rules.Rule{
			{Name: "aws_access_key_id", Severity: "CRITICAL", Pattern: lateSecretAWSRule},
		},
	}
	if err := rs.CompileAll(); err != nil {
		t.Fatalf("compiling rules: %v", err)
	}

	findings := DecodeAndRescan(line, "test.txt", 1, rs, finding.SeverityInfo, Flags{Base64: true})
	for _, f := range findings {
		if f.Secret == secret {
			return
		}
	}
	t.Fatalf("secret at decoded offset 601 not found; got %d findings: %+v", len(findings), findings)
}

func TestRecursiveDecodeFanoutBound(t *testing.T) {
	// Doubly-base64-nested input: line -> inner -> payload. Both the base64
	// and doublebase64 decoders can produce the same intermediate texts, so
	// the visited set has to keep recursion fan-out from exploding.
	secret := "AKIAIOSFODNN7EXAMPLE"
	payload := strings.Repeat("Z", 80) + secret
	inner := base64.StdEncoding.EncodeToString([]byte(payload))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))
	line := `const blob = "` + outer + `"`

	rs := &rules.RuleSet{
		Rules: []rules.Rule{
			{Name: "aws_access_key_id", Severity: "CRITICAL", Pattern: lateSecretAWSRule},
		},
	}
	if err := rs.CompileAll(); err != nil {
		t.Fatalf("compiling rules: %v", err)
	}

	decoders := PrecomputeDecoders(Flags{Base64: true, DoubleBase64: true})
	if len(decoders) == 0 {
		t.Fatal("PrecomputeDecoders returned no decoders for base64+doublebase64")
	}

	start := time.Now()
	findings := DecodeAndRescanWithDecoders(line, "test.txt", 1, rs, finding.SeverityInfo, decoders)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("recursive decode took %v, want prompt return (<2s)", elapsed)
	}
	if len(findings) >= 50 {
		t.Errorf("findings = %d, want <50 (fan-out bound)", len(findings))
	}
}
