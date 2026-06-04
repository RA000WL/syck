package entropy

import "math"

func Shannon(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, ch := range data {
		freq[ch]++
	}
	var entropy float64
	n := float64(len(data))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*1000) / 1000
}

var lowEntropyPatterns = []string{
	"localhost", "example", "test", "mock", "staging",
	"qwerty", "xxxxx", "aaaaa", "12345", "password",
	"passw0rd", "admin", "root", "nobody",
}

var secretContextPatterns = []string{
	"secret", "token", "key", "password", "passwd", "pwd",
	"api_key", "apikey", "access_key", "auth", "bearer",
	"jwt", "private", "credential", "aws", "ghp_",
}

func HasSecretContext(s string) bool {
	lower := toLower(s)
	for _, pat := range secretContextPatterns {
		if contains(lower, pat) {
			return true
		}
	}
	return false
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
