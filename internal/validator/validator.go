package validator

import (
	"strings"
)

// ValidationResult holds the outcome of validating a secret against its provider API.
type ValidationResult struct {
	Valid  bool
	Detail string // e.g. "login: octocat" or "HTTP 401"
}

// Validator validates a single secret against its provider.
type Validator interface {
	Name() string
	Validate(secret string) ValidationResult
}

// registry maps cleaned rule names to validators.
var registry = map[string]Validator{}

// Register adds a validator for the given rule name.
func Register(ruleName string, v Validator) {
	registry[ruleName] = v
}

// Validate looks up the validator for ruleName and runs it.
// Returns the result and true if a validator was found, zero result and false otherwise.
func Validate(ruleName, secret string) (ValidationResult, bool) {
	clean := strings.TrimLeft(ruleName, "abcdefghijklmnopqrstuvwxyz_")
	if v, ok := registry[clean]; ok {
		return v.Validate(strings.TrimSpace(secret)), true
	}
	if v, ok := registry[ruleName]; ok {
		return v.Validate(strings.TrimSpace(secret)), true
	}
	return ValidationResult{}, false
}
