package entropy

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

func Shannon(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, ch := range data {
		freq[ch]++
	}
	var ent float64
	n := float64(utf8.RuneCountInString(data))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		ent -= p * math.Log2(p)
	}
	return math.Round(ent*1000) / 1000
}

// EntropyTokenRe matches 32+ char alphanumeric/base64 tokens.
var EntropyTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{32,}`)

// entropyExcludeRe matches tokens that are just the base64 alphabet or Docker MDU6.
var entropyExcludeRe = regexp.MustCompile(`(?i)(?:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/|MDU6[A-Za-z0-9+/=]{10,})`)

// secretContextRe gates entropy scanning — only fires on lines with secret-related keywords.
var secretContextRe = regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|secret|secret[_-]?key|password|passwd|pwd|token|bearer|auth(?:orization)?|credential|private[_-]?key|access[_-]?key|client[_-]?(?:id|secret)|aws|gcp|azure|s3|encryption[_-]?key|signing[_-]?key|jwt|oauth|ssh[_-]?key)\b`)

// HasSecretContext returns true if line contains a secret-related keyword.
func HasSecretContext(s string) bool {
	return secretContextRe.MatchString(s)
}

// LikelySecret checks if a token is likely a real secret.
// Requires: min length, not all digits, ≥3 char classes, min Shannon entropy.
func LikelySecret(token string, minLen int, minEntropy float64) bool {
	candidate := token
	// strip leading/trailing quotes, parens, backticks
	for len(candidate) > 0 {
		c := candidate[len(candidate)-1]
		if c == '\'' || c == '"' || c == '`' || c == ')' {
			candidate = candidate[:len(candidate)-1]
		} else {
			break
		}
	}
	for len(candidate) > 0 {
		c := candidate[0]
		if c == '\'' || c == '"' || c == '`' || c == '(' {
			candidate = candidate[1:]
		} else {
			break
		}
	}

	if len(candidate) < minLen {
		return false
	}

	// reject all-digit strings
	allDigits := true
	for i := 0; i < len(candidate); i++ {
		if candidate[i] < '0' || candidate[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}

	// require ≥3 of 4 character classes
	classes := 0
	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
	for i := 0; i < len(candidate); i++ {
		c := candidate[i]
		if c >= 'a' && c <= 'z' {
			hasLower = true
		} else if c >= 'A' && c <= 'Z' {
			hasUpper = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		} else if c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '@' || c == '$' || c == '!' || c == '%' || c == '^' || c == '&' || c == '*' || c == '(' || c == ')' {
			hasSpecial = true
		}
	}
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSpecial {
		classes++
	}
	if classes < 3 {
		return false
	}

	return Shannon(candidate) >= minEntropy
}

// IsEntropyTokenMatch returns true if token passes entropy token scan filters.
func IsEntropyTokenMatch(token string) bool {
	if entropyExcludeRe.MatchString(token) {
		return false
	}
	if len(token) < 32 {
		return false
	}
	a := DetectAlphabet(token)
	if a == AlphabetUnknown {
		return LikelySecret(token, 32, 4.5)
	}
	return EntropyByAlphabet(token, a) >= thresholdFor(a)
}

func thresholdFor(a Alphabet) float64 {
	switch a {
	case AlphabetLowerHex, AlphabetUpperHex:
		return 3.0
	default:
		return 4.0
	}
}

func Base64Entropy(s string) float64 {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	return shannonFiltered(s, alphabet)
}

func HexEntropy(s string) float64 {
	const alphabet = "0123456789abcdefABCDEF"
	return shannonFiltered(s, alphabet)
}

func JwtEntropy(s string) float64 {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return shannonFiltered(s, alphabet)
}

func shannonFiltered(s, alphabet string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return 0
		}
		freq[r]++
	}
	var ent float64
	n := float64(utf8.RuneCountInString(s))
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return math.Round(ent*1000) / 1000
}

func EntropyByAlphabet(s string, a Alphabet) float64 {
	switch a {
	case AlphabetLowerHex, AlphabetUpperHex:
		return HexEntropy(s)
	case AlphabetBase64URL, AlphabetJWT:
		return JwtEntropy(s)
	case AlphabetBase64:
		return Base64Entropy(s)
	default:
		return Shannon(s)
	}
}

var mediaPrefixes = []struct {
	prefix []byte
}{
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}}, // PNG
	{[]byte{0xFF, 0xD8, 0xFF}},                               // JPEG
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}},             // GIF87a
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}},             // GIF89a
	{[]byte{0x52, 0x49, 0x46, 0x46}},                         // WebP (RIFF...WEBP at byte 8)
	{[]byte{0x3C, 0x3F, 0x78, 0x6D, 0x6C}},                   // <?xml
	{[]byte{0x3C, 0x73, 0x76, 0x67}},                         // <svg
	{[]byte{0x00, 0x00, 0x01, 0x00}},                         // ICO
	{[]byte{0x49, 0x49, 0x2A, 0x00}},                         // TIFF LE
	{[]byte{0x4D, 0x4D, 0x00, 0x2A}},                         // TIFF BE
	{[]byte{0x42, 0x4D}},                                     // BMP
	{[]byte{0x77, 0x4F, 0x46, 0x46}},                         // WOFF
	{[]byte{0x77, 0x4F, 0x46, 0x32}},                         // WOFF2
	{[]byte{0x00, 0x01, 0x00, 0x00}},                         // TTF
	{[]byte{0x4F, 0x54, 0x54, 0x4F}},                         // OTF
}

var webpSuffix = []byte("WEBP")

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

	sliceLen := len(padded)
	if sliceLen > 20 {
		sliceLen = 20
	}
	sliceLen -= sliceLen % 4

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
				if mp.prefix[0] == 0x52 && mp.prefix[1] == 0x49 {
					if len(decoded) < 12 {
						continue
					}
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
				return true
			}
		}
	}
	return false
}

func HasContextKeyword(line string) bool {
	lower := strings.ToLower(line)
	keywords := []string{
		"secret", "token", "apikey", "api_key", "auth", "bearer",
		"password", "credential", "private", "secret_key", "access_key",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

type ContextualSecret struct {
	Token   string
	Entropy float64
}

func ExtractContextualSecrets(line string, minEntropy float64) []ContextualSecret {
	if !HasContextKeyword(line) {
		return nil
	}
	var results []ContextualSecret
	tokens := EntropyTokenRe.FindAllString(line, -1)
	for _, tok := range tokens {
		if len(tok) < 20 {
			continue
		}
		e := Shannon(tok)
		if e < minEntropy {
			continue
		}
		idx := strings.Index(line, tok)
		if idx > 0 && (line[idx-1] == '/' || line[idx-1] == ':' || line[idx-1] == '@') {
			continue
		}
		// Skip URL path segments (contain multiple / separators)
		if strings.Count(tok, "/") >= 2 {
			continue
		}
		results = append(results, ContextualSecret{Token: tok, Entropy: e})
	}
	return results
}
