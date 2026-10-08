package scanner

// Characterization tests for the dedup skip-set key truncation fixed in
// batch7. All skip-sets compared the first N chars of the secret key, so two
// distinct secrets sharing a 60-char prefix merged into one finding. These
// tests pin the before/after behavior at each distinct path: the decoded
// content pass (ScanContent), the streaming pass (scanFileStreaming), and the
// gzip raw+decoded double pass (ScanFile).

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

// firebase_fcm_key matches: \bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b
// (full match length 152). Tails share the first 60 tail chars, so the two
// distinct secrets share a 72-char prefix. Tails are generated from an LCG
// over the full rule alphabet: a narrow repeated cycle would trip the
// IsFalsePositiveToken base58/alphabet filters.
// charset deliberately avoids '-' (3+ hyphens in a >20-char token trips
// IsFalsePositiveToken's hyphenated-flag-name heuristic) and ':'.
const fcmCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

func fcmTail(seed uint64, n int) string {
	var sb strings.Builder
	x := seed
	for i := 0; i < n; i++ {
		x = x*6364136223846793005 + 1442695040888963407
		sb.WriteByte(fcmCharset[(x>>33)%63])
	}
	return sb.String()
}

func collidingFCMKeys() (a, b string) {
	head := "AAAAAb3dEf7:"
	shared := fcmTail(42, 60)
	endA := fcmTail(1234, 80)
	endB := fcmTail(9876, 80)
	// The rule's trailing \b needs a word char at the tail end on both sides.
	endA = endA[:79] + "z"
	endB = endB[:79] + "z"
	a = head + shared + endA // 4+7+1+60+80 = 152
	b = head + shared + endB
	return a, b
}

func countFCMFindings(fs []finding.Finding) int {
	n := 0
	for _, f := range fs {
		if strings.Contains(f.RuleName, "firebase_fcm_key") {
			n++
		}
	}
	return n
}

func secretsByRule(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		if strings.Contains(f.RuleName, "firebase_fcm_key") {
			out = append(out, f.Secret)
		}
	}
	return out
}

// TestDedupKeyTruncation_ScanContentDecoded covers the ScanContent decoded
// path (scan_content.go + helpers.go skip-set sites): plaintext secret A on
// the line, and base64(B) whose decoded form is a distinct secret B sharing
// A's 72-char prefix. Identical-secret control: base64(A) decodes to A.
func TestDedupKeyTruncation_ScanContentDecoded(t *testing.T) {
	a, b := collidingFCMKeys()
	if len(a) != 152 || len(b) != 152 {
		t.Fatalf("fixture length: a=%d b=%d", len(a), len(b))
	}
	shared := 0
	for i := 0; i < len(a) && i < len(b) && a[i] == b[i]; i++ {
		shared++
	}
	t.Logf("measured shared prefix: %d chars (a=%d b=%d)", shared, len(a), len(b))
	if shared < 60 {
		t.Fatalf("fixture prefix too short: %d", shared)
	}
	if a == b {
		t.Fatal("fixture not distinct")
	}

	rs := loadDefaultRules(t)
	cfg := Config{Rules: rs, MinSeverity: finding.SeverityLow, DecodeBase64: true}

	colliding := `api_key = "` + a + `" backup = "` + base64.StdEncoding.EncodeToString([]byte(b)) + `"`
	got := ScanContent(colliding, "fixture.txt", cfg)
	t.Logf("colliding pair -> %d firebase findings: %v", countFCMFindings(got), secretsByRule(got))
	if n := countFCMFindings(got); n != 2 {
		t.Fatalf("want 2 findings for the colliding pair, got %d", n)
	}

	identical := `api_key = "` + a + `" backup = "` + base64.StdEncoding.EncodeToString([]byte(a)) + `"`
	gotIdent := ScanContent(identical, "fixture.txt", cfg)
	t.Logf("identical secret -> %d firebase findings", countFCMFindings(gotIdent))
	if countFCMFindings(gotIdent) != 1 {
		t.Fatalf("still-merged case must stay 1, got %d", countFCMFindings(gotIdent))
	}
}

// Same collision driven through the streaming path (>1MB file) — covers the
// two scan_stream.go skip-set sites.
func TestDedupKeyTruncation_ScanFileStreaming(t *testing.T) {
	a, b := collidingFCMKeys()
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	padding := strings.Repeat("padding line\n", 1024*1024/12) // >1MB
	line := `api_key = "` + a + `" backup = "` + base64.StdEncoding.EncodeToString([]byte(b)) + `"`
	if err := os.WriteFile(path, []byte(padding+line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rs := loadDefaultRules(t)
	cfg := Config{Workers: 1, MaxFileSize: 100 << 20, Rules: rs, MinSeverity: finding.SeverityLow, DecodeBase64: true}
	got, err := scanFileStreaming(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("streaming colliding pair -> %d firebase findings", countFCMFindings(got))
	if n := countFCMFindings(got); n != 2 {
		t.Fatalf("want 2 findings for the colliding pair, got %d", n)
	}

	path2 := filepath.Join(dir, "big2.txt")
	line2 := `api_key = "` + a + `" backup = "` + base64.StdEncoding.EncodeToString([]byte(a)) + `"`
	if err := os.WriteFile(path2, []byte(padding+line2+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gotIdent, err := scanFileStreaming(path2, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("streaming identical secret -> %d firebase findings", countFCMFindings(gotIdent))
	if countFCMFindings(gotIdent) != 1 {
		t.Fatalf("still-merged case must stay 1, got %d", countFCMFindings(gotIdent))
	}
}

// storedGzip builds a gzip stream that embeds payload as a single stored
// (uncompressed) block, so the payload bytes appear verbatim in the raw file
// AND decompress to the same payload. This lets one fixture exercise both
// passes of the gzip raw+decoded dedup.
func storedGzip(t *testing.T, payload []byte) []byte {
	t.Helper()
	if len(payload) > 65535 {
		t.Fatalf("stored block too large: %d", len(payload))
	}
	var buf bytes.Buffer
	buf.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff})
	buf.WriteByte(0x01) // BFINAL=1, BTYPE=00, rest of byte ignored for stored blocks
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(len(payload)))
	binary.LittleEndian.PutUint16(hdr[2:4], ^uint16(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)
	var tr [4]byte
	binary.LittleEndian.PutUint32(tr[:], crc32.ChecksumIEEE(payload))
	buf.Write(tr[:])
	binary.LittleEndian.PutUint32(tr[:], uint32(len(payload)))
	buf.Write(tr[:])
	return buf.Bytes()
}

// Same collision through ScanFile with DecodeGzip: the gzip pass reports A
// and B; the raw pass would re-report them but must keep deduping.
func TestDedupKeyTruncation_ScanFileGzip(t *testing.T) {
	a, b := collidingFCMKeys()
	dir := t.TempDir()
	payload := `api_key = "` + a + `" backup = "` + base64.StdEncoding.EncodeToString([]byte(b)) + `"` + "\n"
	path := filepath.Join(dir, "f.gz")
	if err := os.WriteFile(path, storedGzip(t, []byte(payload)), 0o644); err != nil {
		t.Fatal(err)
	}
	rs := loadDefaultRules(t)
	cfg := Config{Rules: rs, MinSeverity: finding.SeverityLow, DecodeBase64: true, DecodeGzip: true}
	got, err := ScanFile(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gzip colliding pair -> %d firebase findings", countFCMFindings(got))
	if n := countFCMFindings(got); n != 2 {
		t.Fatalf("want 2 findings for the colliding pair, got %d", n)
	}

	payload2 := `api_key = "` + a + `" backup = "` + base64.StdEncoding.EncodeToString([]byte(a)) + `"` + "\n"
	path2 := filepath.Join(dir, "f2.gz")
	if err := os.WriteFile(path2, storedGzip(t, []byte(payload2)), 0o644); err != nil {
		t.Fatal(err)
	}
	gotIdent, err := ScanFile(path2, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gzip identical secret -> %d firebase findings", countFCMFindings(gotIdent))
	if countFCMFindings(gotIdent) != 1 {
		t.Fatalf("still-merged case must stay 1, got %d", countFCMFindings(gotIdent))
	}
}
