package decoder

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var jwtCandidateRE = regexp.MustCompile(`\b[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)

func tryJWT(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range jwtCandidateRE.FindAllString(line, -1) {
		parts := strings.Split(m, ".")
		if len(parts) != 3 {
			continue
		}
		payload := parts[1]
		for len(payload)%4 != 0 {
			payload += "="
		}
		decoded, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(payload)
			if err != nil {
				continue
			}
		}
		if !isPrintableUTF8(decoded) {
			continue
		}
		results = append(results, DecodeResult{SourceTag: "jwt", Text: string(decoded)})
	}
	return results
}
