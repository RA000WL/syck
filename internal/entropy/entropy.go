package entropy

import (
	"math"
	"regexp"
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
	return LikelySecret(token, 32, 4.5)
}

var lowEntropyPatterns = []string{
	"localhost", "example", "test", "mock", "staging",
	"qwerty", "xxxxx", "aaaaa", "12345", "password",
	"passw0rd", "admin", "root", "nobody",
}

func IsLowEntropy(s string) bool {
	lower := toLower(s)
	for _, pat := range lowEntropyPatterns {
		if contains(lower, pat) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
