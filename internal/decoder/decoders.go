package decoder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var (
	base64CandidateRE = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)
	hexCandidateRE    = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}){10,}\b`)
	unicodeEscapeRE   = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	urlEncodedRE      = regexp.MustCompile(`%([0-9a-fA-F]{2})`)

	base64MinLen = 32
	hexMinLen    = 20
)

type DecodeResult struct {
	SourceTag string
	Text      string
}

func tryBase64(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range base64CandidateRE.FindAllString(line, -1) {
		if len(m) < base64MinLen {
			continue
		}
		padding := 4 - len(m)%4
		if padding != 4 {
			m += strings.Repeat("=", padding)
		}
		decoded, err := base64.StdEncoding.DecodeString(m)
		if err != nil {
			decoded, err = base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(m)
			if err != nil {
				continue
			}
		}
		if !isPrintableUTF8(decoded) {
			continue
		}
		results = append(results, DecodeResult{SourceTag: "base64", Text: string(decoded)})
	}
	return results
}

func tryHex(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range hexCandidateRE.FindAllString(line, -1) {
		if len(m) < hexMinLen {
			continue
		}
		if hasMixedCase(m) {
			continue
		}
		decoded, err := hex.DecodeString(m)
		if err != nil {
			continue
		}
		if !isPrintableUTF8(decoded) {
			continue
		}
		text := string(decoded)
		trimmed := strings.TrimSpace(strings.ToLower(strings.TrimRight(text, "x")))
		if trimmed == "" || trimmed == "hex" {
			continue
		}
		results = append(results, DecodeResult{SourceTag: "hex", Text: text})
	}
	return results
}

var urlEncodedSingleRE = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

func tryUnicodeEscapes(line string) []DecodeResult {
	if !strings.Contains(line, "\\u") {
		return nil
	}
	decoded := unicodeEscapeRE.ReplaceAllStringFunc(line, func(m string) string {
		hexStr := m[2:]
		var r rune
		fmt.Sscanf(hexStr, "%x", &r)
		return string(r)
	})
	if decoded == line {
		return nil
	}
	return []DecodeResult{{SourceTag: "unicode", Text: decoded}}
}

func tryURLEncoded(line string) []DecodeResult {
	if !strings.Contains(line, "%") {
		return nil
	}
	decoded := urlEncodedRE.ReplaceAllStringFunc(line, func(m string) string {
		var b byte
		fmt.Sscanf(m[1:], "%02x", &b)
		return string(b)
	})
	if decoded == line {
		return nil
	}
	return []DecodeResult{{SourceTag: "url", Text: decoded}}
}

func isPrintableUTF8(data []byte) bool {
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return printable >= len(data)/2
}

func hasMixedCase(s string) bool {
	hasUpper := false
	hasLower := false
	for _, ch := range s {
		if ch >= 'A' && ch <= 'F' {
			hasUpper = true
		}
		if ch >= 'a' && ch <= 'f' {
			hasLower = true
		}
	}
	return hasUpper && hasLower
}

type Flags struct {
	Base64       bool
	Hex          bool
	Unicode      bool
	URL          bool
	Base64URL    bool
	JWT          bool
	DoubleBase64 bool
}

func (f Flags) HasAny() bool {
	return f.Base64 || f.Hex || f.Unicode || f.URL || f.Base64URL || f.JWT || f.DoubleBase64
}

var defaultRegistry = NewRegistry()

func init() {
	defaultRegistry.Register("base64", tryBase64)
	defaultRegistry.Register("base64url", tryBase64URL)
	defaultRegistry.Register("hex", tryHex)
	defaultRegistry.Register("unicode", tryUnicodeEscapes)
	defaultRegistry.Register("url", tryURLEncoded)
	defaultRegistry.Register("jwt", tryJWT)
	defaultRegistry.Register("doublebase64", tryDoubleBase64)
}

func activeDecoders(flags Flags) []Decoder {
	return defaultRegistry.Active(flags)
}
