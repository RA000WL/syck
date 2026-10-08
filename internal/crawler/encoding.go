package crawler

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

var charsetRe = regexp.MustCompile(`charset=([^\s;]+)`)

// DetectEncoding checks the Content-Type header and HTML meta tags
// for charset declarations. Returns the charset name or "" if not found.
func DetectEncoding(contentType string, body []byte) string {
	// 1. Check Content-Type header
	if ct := charsetRe.FindStringSubmatch(contentType); len(ct) > 1 {
		return strings.ToLower(strings.Trim(ct[1], "\"'"))
	}

	// 2. Check <meta charset="..."> (HTML5)
	// Only check first 1024 bytes for performance
	sample := body
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	sampleStr := string(sample)

	// <meta charset="utf-8">
	if m := regexp.MustCompile(`(?i)<meta[^>]+charset=["']?([a-zA-Z0-9_-]+)`).FindStringSubmatch(sampleStr); len(m) > 1 {
		return strings.ToLower(m[1])
	}

	// 3. Check <meta http-equiv="Content-Type" content="text/html; charset=...">
	if m := regexp.MustCompile(`(?i)<meta[^>]+content=["'][^"']*charset=([a-zA-Z0-9_-]+)`).FindStringSubmatch(sampleStr); len(m) > 1 {
		return strings.ToLower(m[1])
	}

	// 4. Check BOM (Byte Order Mark)
	if len(body) >= 3 {
		if body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF {
			return "utf-8"
		}
		if body[0] == 0xFE && body[1] == 0xFF {
			return "utf-16be"
		}
		if body[0] == 0xFF && body[1] == 0xFE {
			return "utf-16le"
		}
	}

	return ""
}

// ConvertToUTF8 converts body bytes to UTF-8 based on the detected charset.
// Returns the converted bytes and true if conversion was performed,
// or the original bytes and false if no conversion was needed.
func ConvertToUTF8(body []byte, charset string) ([]byte, bool) {
	if charset == "" || charset == "utf-8" || charset == "us-ascii" {
		return body, false
	}

	// For ISO-8859-x and Windows-125x, use a simple byte mapping
	// For other charsets, we'd need golang.org/x/text — skip for now
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin1", "iso8859-1":
		return iso88591ToUTF8(body), true
	case "windows-1252", "cp1252", "win-1252":
		return windows1252ToUTF8(body), true
	case "ascii", "us-ascii", "iso-ir-6":
		return body, false // ASCII is subset of UTF-8
	default:
		// Unknown charset — return as-is, don't break scanning
		return body, false
	}
}

// iso88591ToUTF8 converts ISO-8859-1 bytes to UTF-8.
// ISO-8859-1 maps directly to Unicode code points U+0000 to U+00FF.
func iso88591ToUTF8(body []byte) []byte {
	var buf strings.Builder
	buf.Grow(len(body))
	for _, b := range body {
		if b < 0x80 {
			buf.WriteByte(b)
		} else {
			// Encode as 2-byte UTF-8
			buf.WriteRune(rune(b))
		}
	}
	return []byte(buf.String())
}

// windows1252ToUTF8 converts Windows-1252 bytes to UTF-8.
// Windows-1252 is a superset of ISO-8859-1 with different mappings
// for 0x80-0x9F range.
func windows1252ToUTF8(body []byte) []byte {
	var buf strings.Builder
	buf.Grow(len(body))
	for _, b := range body {
		if b < 0x80 {
			buf.WriteByte(b)
		} else if b >= 0xA0 {
			// 0xA0-0xFF maps directly to Unicode
			buf.WriteRune(rune(b))
		} else {
			// 0x80-0x9F: Windows-1252 specific mappings
			buf.WriteRune(cp1252ToUnicode[b-0x80])
		}
	}
	return []byte(buf.String())
}

// cp1252ToUnicode maps Windows-1252 bytes 0x80-0x9F to Unicode code points.
var cp1252ToUnicode = [32]rune{
	0x20AC, // 0x80 €
	0x0081, // 0x81 (undefined)
	0x201A, // 0x82 ‚
	0x0192, // 0x83 ƒ
	0x201E, // 0x84 „
	0x2026, // 0x85 …
	0x2020, // 0x86 †
	0x2021, // 0x87 ‡
	0x02C6, // 0x88 ˆ
	0x2030, // 0x89 ‰
	0x0160, // 0x8A Š
	0x2039, // 0x8B ‹
	0x0152, // 0x8C Œ
	0x008D, // 0x8D (undefined)
	0x017D, // 0x8E Ž
	0x008F, // 0x8F (undefined)
	0x0090, // 0x90 (undefined)
	0x2018, // 0x91 '
	0x2019, // 0x92 '
	0x201C, // 0x93 "
	0x201D, // 0x94 "
	0x2022, // 0x95 •
	0x2013, // 0x96 –
	0x2014, // 0x97 —
	0x02DC, // 0x98 ˜
	0x2122, // 0x99 ™
	0x0161, // 0x9A š
	0x203A, // 0x9B ›
	0x0153, // 0x9C œ
	0x009D, // 0x9D (undefined)
	0x017E, // 0x9E ž
	0x0178, // 0x9F Ÿ
}

// FetchWithEncoding fetches a URL and auto-detects encoding, returning UTF-8 content.
func FetchWithEncoding(client *http.Client, rawURL string, ua string) (string, string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", "", err
	}
	if ua == "" {
		ua = RandomUserAgent()
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", io.ErrUnexpectedEOF
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return "", "", err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Detect and convert encoding
	charset := DetectEncoding(contentType, body)
	utf8Body, _ := ConvertToUTF8(body, charset)

	return string(utf8Body), contentType, nil
}
