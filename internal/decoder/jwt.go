package decoder

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// jwtCandidateRE matches header.payload.signature; the payload segment
// tolerates up to two trailing "=" padding chars (padded JWT dialects).
var jwtCandidateRE = regexp.MustCompile(`\b[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+={0,2}\.[A-Za-z0-9_\-]+\b`)

func tryJWT(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range jwtCandidateRE.FindAllString(line, -1) {
		parts := strings.Split(m, ".")
		if len(parts) != 3 {
			continue
		}
		unpadded := parts[1]
		payload := unpadded
		for len(payload)%4 != 0 {
			payload += "="
		}
		decoded, err := base64.URLEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(unpadded)
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

// IsJWTExpired checks if a JWT token's exp claim has passed.
func IsJWTExpired(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload := parts[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return false
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return false
	}
	if claims.Exp == 0 {
		return false
	}
	return time.Now().Unix() > claims.Exp
}
