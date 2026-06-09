package entropy

import "strings"

type Alphabet int

const (
	AlphabetUnknown Alphabet = iota
	AlphabetLowerHex
	AlphabetUpperHex
	AlphabetBase64
	AlphabetBase64URL
	AlphabetJWT
)

func DetectAlphabet(s string) Alphabet {
	if len(s) == 0 {
		return AlphabetUnknown
	}
	if strings.ContainsAny(s, "-_") && isAlphanumericPlus(s) {
		if strings.Contains(s, "-") && strings.Contains(s, "_") && !strings.ContainsAny(s, "/+") {
			return AlphabetJWT
		}
		return AlphabetBase64URL
	}
	if isAll(s, "0123456789abcdefABCDEF") {
		hasUpper := false
		for _, r := range s {
			if r >= 'A' && r <= 'F' {
				hasUpper = true
				break
			}
		}
		if hasUpper {
			return AlphabetUpperHex
		}
		return AlphabetLowerHex
	}
	if isBase64(s) {
		return AlphabetBase64
	}
	return AlphabetUnknown
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return false
		}
	}
	return true
}

func isAlphanumericPlus(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func isAll(s, alphabet string) bool {
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func (a Alphabet) String() string {
	switch a {
	case AlphabetLowerHex:
		return "hex"
	case AlphabetUpperHex:
		return "hex"
	case AlphabetBase64:
		return "base64"
	case AlphabetBase64URL:
		return "base64url"
	case AlphabetJWT:
		return "jwt"
	default:
		return "unknown"
	}
}

func isBase64(s string) bool {
	if !isAlphanumeric(strings.TrimRight(s, "=")) {
		return false
	}
	hasSlash, hasPlus := strings.ContainsRune(s, '/'), strings.ContainsRune(s, '+')
	hasPadding := strings.HasSuffix(s, "=")
	if hasSlash || hasPlus || hasPadding {
		return true
	}
	return false
}
