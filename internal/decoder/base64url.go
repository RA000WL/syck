package decoder

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var base64URLCandidateRE = regexp.MustCompile(`\b[A-Za-z0-9\-_]{32,}={0,2}`)

func tryBase64URL(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range base64URLCandidateRE.FindAllString(line, -1) {
		if !strings.ContainsAny(m, "-_") {
			continue
		}
		if len(m) < base64MinLen {
			continue
		}
		for len(m)%4 != 0 {
			m += "="
		}
		decoded, err := base64.RawURLEncoding.DecodeString(m)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(m)
			if err != nil {
				continue
			}
		}
		if !isPrintableUTF8(decoded) {
			continue
		}
		results = append(results, DecodeResult{SourceTag: "base64url", Text: string(decoded)})
	}
	return results
}
