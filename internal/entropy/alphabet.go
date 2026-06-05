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
	if strings.ContainsAny(s, "-_") && isAlphanumeric(s) {
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

func isAll(s, alphabet string) bool {
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func isBase64(s string) bool {
	if !isAlphanumeric(strings.TrimRight(s, "=")) {
		return false
	}
	hasSlash, hasPlus := strings.ContainsRune(s, '/'), strings.ContainsRune(s, '+')
	hasPadding := strings.HasSuffix(s, "=") || strings.HasSuffix(s, "==")
	if hasSlash || hasPlus || hasPadding {
		return true
	}
	return false
}
