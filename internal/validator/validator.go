package validator

import "strings"

type State int

const (
	StateUnknown   State = 0
	StatePotential State = 1
	StateLikely    State = 2
	StateVerified  State = 3
)

type ValidationResult struct {
	Valid  bool
	Detail string
	State  State
}

type Provider interface {
	Name() string
	Validate(secret string) ValidationResult
}

type Validator interface {
	Name() string
	Validate(secret string) ValidationResult
}

var registry = map[string]Validator{}

func Register(ruleName string, v Validator) {
	registry[ruleName] = v
}

func Validate(ruleName, secret string) (ValidationResult, bool) {
	clean := ruleName
	if i := strings.Index(clean, "_"); i >= 0 {
		clean = clean[i+1:]
	}
	for _, prefix := range []string{"base64_", "hex_", "url_", "unicode_"} {
		clean = strings.TrimPrefix(clean, prefix)
	}
	if v, ok := registry[clean]; ok {
		return v.Validate(strings.TrimSpace(secret)), true
	}
	if v, ok := registry[ruleName]; ok {
		return v.Validate(strings.TrimSpace(secret)), true
	}
	return ValidationResult{}, false
}
