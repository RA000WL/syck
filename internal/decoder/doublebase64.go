package decoder

import (
	"encoding/base64"
	"regexp"
)

var base64OnceMoreRE = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)

func tryDoubleBase64(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range base64OnceMoreRE.FindAllString(line, -1) {
		decoded, err := decodeLenientBase64(m)
		if err != nil {
			continue
		}
		if !isPrintableUTF8(decoded) {
			continue
		}
		text := string(decoded)
		if base64OnceMoreRE.MatchString(text) {
			results = append(results, DecodeResult{SourceTag: "doublebase64", Text: text})
		}
	}
	return results
}

func decodeLenientBase64(s string) ([]byte, error) {
	for len(s)%4 != 0 {
		s += "="
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(s)
}
