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
	// Fast path: ASCII-only input uses a fixed array (zero GC).
	allASCII := true
	var freq [256]int
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b > 127 {
			allASCII = false
			break
		}
		freq[b]++
	}
	if allASCII {
		var ent float64
		n := float64(len(data))
		for _, count := range freq {
			if count == 0 {
				continue
			}
			p := float64(count) / n
			ent -= p * math.Log2(p)
		}
		return math.Round(ent*1000) / 1000
	}
	// Slow path: non-ASCII, use rune map.
	freq2 := make(map[rune]int)
	for _, ch := range data {
		freq2[ch]++
	}
	var ent float64
	n := float64(utf8.RuneCountInString(data))
	for _, count := range freq2 {
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

// isMostlyAlphabet checks if a token is >70% composed of a sequential alphabet.
// This catches tokens like "abcdefghijklmnopqrstuvwxyz0123456789" (test values)
// but NOT "sk_live_abcdefghijklmnopqrstuvwxyz123456" (real key with prefix).
func isMostlyAlphabet(tok, alphabet string) bool {
	if len(tok) < 16 {
		return false
	}
	seqMatches := 0
	seqIdx := 0
	for i := 0; i < len(tok); i++ {
		if seqIdx < len(alphabet) && tok[i] == alphabet[seqIdx] {
			seqMatches++
			seqIdx++
		}
	}
	ratio := float64(seqMatches) / float64(len(tok))
	return ratio > 0.7
}

// isBase58Alphabet checks if a token is a full or near-full base58 alphabet string.
// Base58 = 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz (no 0/I/O/l)
func isBase58Alphabet(tok string) bool {
	if len(tok) < 40 {
		return false
	}
	const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	lower := strings.ToLower(tok)
	matchCount := 0
	bi := 0
	for i := 0; i < len(lower) && bi < len(b58); i++ {
		if lower[i] == b58[bi] {
			matchCount++
			bi++
		}
	}
	return float64(matchCount)/float64(len(b58)) > 0.85
}

// isSortedSequence checks if a token's characters are in ascending order.
// Alphabet/charset strings are sorted; real secrets are randomly ordered.
// Allows trailing special chars (base64 padding, hyphens).
func isSortedSequence(tok string) bool {
	if len(tok) < 30 {
		return false
	}
	// Strip trailing non-alphanumeric chars
	end := len(tok)
	for end > 0 && !((tok[end-1] >= 'a' && tok[end-1] <= 'z') || (tok[end-1] >= 'A' && tok[end-1] <= 'Z') || (tok[end-1] >= '0' && tok[end-1] <= '9')) {
		end--
	}
	if end < 30 {
		return false
	}
	sorted := true
	for i := 1; i < end; i++ {
		if tok[i] <= tok[i-1] {
			sorted = false
			break
		}
	}
	return sorted
}

// isFalsePositiveToken rejects tokens that look like secrets but aren't.
func IsFalsePositiveToken(tok string) bool {
	lower := strings.ToLower(tok)

	// Base alphabets: reject tokens that are mostly sequential base58/base62 chars
	if isMostlyAlphabet(lower, "0123456789abcdef") {
		return true
	}

	// Full base58 alphabet (with/without common variants)
	if isBase58Alphabet(tok) {
		return true
	}

	// Sorted character sequences (alphabet/charset listings)
	if isSortedSequence(tok) {
		return true
	}

	// CSS variables (start with --)
	if strings.HasPrefix(tok, "--") {
		return true
	}

	// Trailing = on camelCase/snake_case variable names (JS property assignments)
	if strings.HasSuffix(tok, "=") && len(tok) > 8 {
		stripped := tok[:len(tok)-1]
		isVarName := true
		for i := 0; i < len(stripped); i++ {
			c := stripped[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				isVarName = false
				break
			}
		}
		if isVarName {
			return true
		}
	}

	// Hyphenated experiment/feature-flag names (e.g. cowork-activation-checklist-v2-fired-completed)
	hyphens := strings.Count(tok, "-")
	if hyphens >= 3 && len(tok) > 20 {
		return true
	}

	// Swift/ObjC function names
	if strings.Contains(lower, "swift_") || strings.Contains(lower, "unboxfrom") {
		return true
	}

	// snake_case internal names: all lowercase letters + digits + underscores only
	if strings.Contains(tok, "_") && !strings.ContainsAny(tok, "+/=-") {
		allSnake := true
		for i := 0; i < len(tok); i++ {
			c := tok[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				allSnake = false
				break
			}
		}
		if allSnake {
			transitions := 0
			for i := 1; i < len(tok); i++ {
				if (tok[i] >= 'a' && tok[i] <= 'z') != (tok[i-1] >= 'a' && tok[i-1] <= 'z') ||
					(tok[i] >= '0' && tok[i] <= '9') != (tok[i-1] >= '0' && tok[i-1] <= '9') {
					transitions++
				}
			}
			if transitions > 5 {
				return true
			}
		}
	}

	// URL path segments (contain @ for images like opengraph-image@2x.png)
	if strings.Count(tok, "@") == 1 && strings.Contains(tok, ".") &&
		(strings.HasSuffix(tok, ".png") || strings.HasSuffix(tok, ".jpg") || strings.HasSuffix(tok, ".svg") ||
			strings.HasSuffix(tok, ".js") || strings.HasSuffix(tok, ".css") || strings.HasSuffix(tok, ".woff")) {
		return true
	}

	// Common placeholder/template values
	if knownPlaceholderRe.MatchString(tok) {
		return true
	}

	return false
}

// knownPlaceholderRe matches common placeholder/template token values.
var knownPlaceholderRe = regexp.MustCompile(`(?i)^(?:bare[-_]?token|your[-_]?(?:token|key|secret|password)|test[-_]?(?:token|key|secret|value|password)|example[-_]?(?:token|key|secret)|placeholder[-_]?(?:token|key|secret)?|xxx{1,10}|changeme|change[-_]?me|dummy|sample|fake[-_]?(?:secret|token|key|password)|temp[-_]?(?:token|key|secret)|not[-_]?(?:a[-_])?secret|token[-_]?here|secret[-_]?here|key[-_]?here|insert[-_]?(?:key|token|secret)|your[-_]?(?:api[-_]?key)|your[-_]?(?:api[-_]?key[-_]?here)|REPLACE[-_]?ME|TODO[-_]?(?:SECRET|TOKEN|KEY)|FIXME[-_]?(?:SECRET|TOKEN|KEY)|NOT[-_]?A[-_]?REAL[-_]?SECRET)$`)

// kvPlaceholderRe matches key=value patterns where the value is a placeholder.
var kvPlaceholderRe = regexp.MustCompile(`(?i)^(?:[a-z][a-z0-9]*[-_]?){1,4}\s*[:=]\s*['"](.+?)['"]$`)

// imageFileRe matches image filenames that would falsely match email regex.
// E.g. opengraph-image@2x.png, og-image@1x.jpg, icon@2x.svg
var imageFileRe = regexp.MustCompile(`(?i)^[\w.\-]+@\d+x?\.\w{2,5}$`)

// IsFalsePositiveSecret checks a key=value matched string for placeholder values.
// E.g. Token="bare-token" → extracts "bare-token" → checks placeholderRe.
func IsFalsePositiveSecret(s string) bool {
	if m := kvPlaceholderRe.FindStringSubmatch(s); m != nil {
		val := strings.TrimSpace(m[1])
		if IsFalsePositiveToken(val) {
			return true
		}
		lowerVal := strings.ToLower(val)
		if knownPlaceholderRe.MatchString(lowerVal) {
			return true
		}
	}
	return false
}

// IsFalsePositiveEmail checks if an email address match is a false positive
// (e.g. image filenames like opengraph-image@2x.png).
func IsFalsePositiveEmail(s string) bool {
	if imageFileRe.MatchString(s) {
		return true
	}
	// Reject emails with image extensions as domain
	lower := strings.ToLower(s)
	if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") ||
		strings.HasSuffix(lower, ".jpeg") || strings.HasSuffix(lower, ".gif") ||
		strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".webp") ||
		strings.HasSuffix(lower, ".ico") || strings.HasSuffix(lower, ".woff") ||
		strings.HasSuffix(lower, ".woff2") || strings.HasSuffix(lower, ".js") ||
		strings.HasSuffix(lower, ".css") || strings.HasSuffix(lower, ".ttf") {
		return true
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
		if IsFalsePositiveToken(tok) {
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
