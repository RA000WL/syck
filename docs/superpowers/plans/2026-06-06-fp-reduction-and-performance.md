# V1.5 FP Reduction & Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce false positives from base64-encoded media and prevent performance degradation on oversized lines.

**Architecture:** (1) `IsMediaToken()` in entropy package checks magic bytes of decoded base64 media tokens; (2) `MaxScanLineLen` in scanner Config gates per-line scanning above a configurable threshold tiering endpoint extraction to handle large JS bundles.

**Tech Stack:** Go stdlib `encoding/base64`, `scanner.Config`, `cmd/scan.go` cobra flag

---

### Task 1: Add IsMediaToken to entropy package

**Files:**
- Modify: `internal/entropy/entropy.go` — add `IsMediaToken()` function + magic byte tables
- Test: `internal/entropy/entropy_extended_test.go` — tests for all media formats
- Add: `encoding/base64` to imports

- [ ] **Step 1: Write the failing tests**

Append to `internal/entropy/entropy_extended_test.go`:

```go
package entropy

import "testing"

func TestIsMediaTokenPNG(t *testing.T) {
	// 1x1 red pixel PNG
	tok := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	if !IsMediaToken(tok) {
		t.Error("expected PNG to be detected as media")
	}
}

func TestIsMediaTokenJPEG(t *testing.T) {
	// tiny JPEG
	tok := "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYI5SDFUJRVxQyMkJzNictI2QwM0YzNERmcVJjVUdjhKS09SVGFhcZJGlcYW5jZSUISYoM0NUV1JjZGVjZGVoYmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9sAQwAaGhopHSlBJiZBQi8vL0JHPz4+P0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dH/9sAQwEaKSk0JjQ/KCg/Rz81P0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0f/dAAQAAf/aAAwDAQACEQMRAD8A"
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
	// <svg> prefix
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

func TestIsMediaTokenWOFF(t *testing.T) {
	// d09GRg decodes to \x77\x4F\x46\x46 (WOFF magic)
	tok := "d09GRgABAAAAAACwAAAAAAADAAgA"
	if !IsMediaToken(tok) {
		t.Error("expected WOFF to be detected as media")
	}
}

func TestIsMediaTokenWOFF2(t *testing.T) {
	// d09GMg decodes to \x77\x4F\x46\x32 (WOFF2 magic)
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

func TestIsMediaTokenRandomString(t *testing.T) {
	// Real secret-like strings should NOT be flagged
	tokens := []string{
		"sk_xxxxxxxxxxxxxxxx",
		"ghp_xxxxxxxxxxxxxxxx",
		"AKIAxxxxxxxxxxxxxxxx",
	}
	for _, tok := range tokens {
		if IsMediaToken(tok) {
			t.Errorf("expected %q to NOT be detected as media", tok)
		}
	}
}

func TestIsMediaTokenInvalidBase64(t *testing.T) {
	// Invalid base64 should NOT panic, should return false
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/entropy/ -run TestIsMediaToken -v`
Expected: FAIL with `undefined: IsMediaToken`

- [ ] **Step 3: Write minimal implementation**

At the end of `internal/entropy/entropy.go`, add:

```go
import "encoding/base64"

var mediaPrefixes = []struct {
	prefix []byte
}{
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}}, // PNG
	{[]byte{0xFF, 0xD8, 0xFF}},                                   // JPEG
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}},               // GIF87a
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}},               // GIF89a
	{[]byte{0x52, 0x49, 0x46, 0x46}},                             // WebP (RIFF...WEBP at byte 8)
	{[]byte{0x3C, 0x3F, 0x78, 0x6D, 0x6C}},                       // <?xml
	{[]byte{0x3C, 0x73, 0x76, 0x67}},                              // <svg
	{[]byte{0x00, 0x00, 0x01, 0x00}},                              // ICO
	{[]byte{0x49, 0x49, 0x2A, 0x00}},                              // TIFF LE
	{[]byte{0x4D, 0x4D, 0x00, 0x2A}},                              // TIFF BE
	{[]byte{0x42, 0x4D}},                                           // BMP
	{[]byte{0x77, 0x4F, 0x46, 0x46}},                              // WOFF
	{[]byte{0x77, 0x4F, 0x46, 0x32}},                              // WOFF2
	{[]byte{0x00, 0x01, 0x00, 0x00}},                              // TTF
	{[]byte{0x4F, 0x54, 0x54, 0x4F}},                              // OTF
}

var webpSuffix = []byte("WEBP")

// IsMediaToken checks if a token is base64-encoded media (image, font, etc.)
// rather than a secret. Returns true to indicate the token should be filtered.
func IsMediaToken(tok string) bool {
	if len(tok) < 8 {
		return false
	}

	padded := tok
	switch len(padded) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}

	// Decode only enough bytes for longest magic sequence (PNG: 8 bytes)
	sliceLen := len(padded)
	if sliceLen > 20 {
		sliceLen = 20
	}
	sliceLen -= sliceLen % 4 // align to base64 group boundary

	decoded, err := base64.StdEncoding.DecodeString(padded[:sliceLen])
	if err != nil || len(decoded) < 4 {
		return false
	}

	for _, mp := range mediaPrefixes {
		if len(decoded) >= len(mp.prefix) {
			match := true
			for i, b := range mp.prefix {
				if decoded[i] != b {
					match = false
					break
				}
			}
			if match {
				// Special case: WebP is RIFF + ... + WEBP at offset 8
				if mp.prefix[0] == 0x52 && mp.prefix[1] == 0x49 { // starts with "RI"
					if len(decoded) >= 12 {
						webpMatch := true
						for i, b := range webpSuffix {
							if decoded[8+i] != b {
								webpMatch = false
								break
							}
						}
						if !webpMatch {
							continue
						}
					}
				}
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Fix imports in entropy.go**

Update the import block:
```go
import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/entropy/ -run TestIsMediaToken -v`
Expected: PASS

- [ ] **Step 6: Run full entropy test suite**

Run: `go test ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/entropy/entropy.go internal/entropy/entropy_extended_test.go
git commit -m "feat: add IsMediaToken filter for base64-encoded media false positives"
```

---

### Task 2: Wire IsMediaToken into scanContent entropy path

**Files:**
- Modify: `internal/scanner/scan.go` — add media token filter after entropy mux

- [ ] **Step 1: Add the filter gate**

In `scanContent`, after the `skipSecrets` check (around line 449), add:

```go
				if skipSecrets != nil {
					key := tok
					if len(key) > 60 {
						key = key[:60]
					}
					if skipSecrets[key] {
						continue
					}
				}
				// --- ADD THIS BLOCK ---
				if entropy.IsMediaToken(tok) {
					continue
				}
				// --- END ADD ---
				col := strings.Index(line, tok)
```

- [ ] **Step 2: Run scanner tests**

Run: `go test ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `go test ./...`
Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/scan.go
git commit -m "feat: wire IsMediaToken filter into scanContent entropy path"
```

---

### Task 3: Add MaxScanLineLen to scanner Config and wire into scanContent

**Files:**
- Modify: `internal/scanner/scanner.go` — add `MaxScanLineLen int`
- Modify: `internal/scanner/scan.go` — gate per-line scanning

- [ ] **Step 1: Add MaxScanLineLen to Config**

In `internal/scanner/scanner.go`, add to `Config` struct:
```go
	GitHistory      bool
	MaxScanLineLen  int     // skip per-line scanning on lines exceeding this length (0=unlimited)
```

- [ ] **Step 2: Gate the line loop in scanContent**

In `internal/scanner/scan.go`, around line 369, before the line loop:

```go
	lines := strings.Split(content, "\n")

	df := decoder.Flags{
```

Add the gate inside the loop, after `lineNum++`:

```go
		lineNum++

		if cfg.MaxScanLineLen > 0 && len(line) > cfg.MaxScanLineLen {
			if cfg.Debug {
				longLineCount++
				if longLineCount <= 10 {
					fmt.Fprintf(os.Stderr, "[debug] skipping long line (%d bytes) in %s:%d\n",
						len(line), path, lineNum)
				}
			}
			continue
		}
```

Add `var longLineCount int` before the loop:

```go
	var findings []finding.Finding
	var longLineCount int

	if cfg.JSBeautify && content != "" && isJSFile(path) && tagPrefix == "" {
		content = jsrecon.Beautify(content)
	}
```

- [ ] **Step 3: Add fmt to the scan.go import block**

```go
import (
	"bufio"
	"fmt"
	"os"
	...
)
```

- [ ] **Step 4: Run scanner tests**

Run: `go test ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `go test ./...`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/scan.go internal/scanner/scanner.go
git commit -m "feat: add MaxScanLineLen to gate per-line scanning on oversized lines"
```

---

### Task 4: Add --max-scan-line-len CLI flag

**Files:**
- Modify: `cmd/scan.go` — add flag var, register, wire to scanCfg

- [ ] **Step 1: Add flag variable**

Add to the `var` block in `cmd/scan.go`:
```go
	gitHistory      bool
	validate        bool
	verify          bool
	verifyRate      int
	ignoreFile      string
	maxScanLineLen  int
```

- [ ] **Step 2: Register the flag**

Add to `init()`:
```go
	scanCmd.Flags().IntVar(&maxScanLineLen, "max-scan-line-len", 100000, "skip per-line scanning on lines exceeding this length (0=unlimited)")
```

- [ ] **Step 3: Wire into scanCfg**

In `runScan()`:
```go
	scanCfg := scanner.Config{
		...
		GitHistory:      gitHistory,
		MaxScanLineLen:  maxScanLineLen,
	}
```

- [ ] **Step 4: Build the project**

Run: `go build ./...`
Expected: no errors

- [ ] **Step 5: Verify the flag works**

Run: `/tmp/syck scan --help 2>&1 | grep max-scan-line-len`
Expected: shows `--max-scan-line-len` with default 100000

- [ ] **Step 6: Commit**

```bash
git add cmd/scan.go
git commit -m "feat: add --max-scan-line-len CLI flag"
```

---

### Task 5: Integration — verify on vulnbank.org

**Files:** none (run integration test)

- [ ] **Step 1: Build the binary**

```bash
go build -o /tmp/syck .
```

- [ ] **Step 2: Scan vulnbank.org with default settings**

```bash
/tmp/syck scan -u https://www.vulnbank.org/ 2>&1 | head -20
```
Expected: swagger-ui-bundle.js line 1313 findings still present (endpoint extraction works), but no base64-image findings in swagger-ui.css (`IsMediaToken` should filter those).

- [ ] **Step 3: Verify performance — large file downloaded and scanned**

Check scan time: should be fast (~2-5 seconds for vulnbank).

- [ ] **Step 4: Run full test suite one final time**

```bash
go test ./... && gofmt -l .
```
Expected: all pass, no gofmt issues
