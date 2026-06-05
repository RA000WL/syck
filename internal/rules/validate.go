package rules

import (
	"fmt"
	"regexp"
	"strings"
)

var validSeverities = map[string]bool{
	"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

type RuleValidator struct{}

func NewRuleValidator() *RuleValidator { return &RuleValidator{} }

func (v *RuleValidator) Validate(rs RuleSet) error {
	seen := map[string]int{}
	for i, r := range rs.Rules {
		if r.Name == "" {
			return fmt.Errorf("rule %d: empty name", i)
		}
		if !validSeverities[strings.ToUpper(r.Severity)] {
			return fmt.Errorf("rule %q: invalid severity %q", r.Name, r.Severity)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("rule %q: bad pattern: %w", r.Name, err)
		}
		key := strings.ToLower(r.Name)
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("rule %q: duplicate name (also at index %d)", r.Name, prev)
		}
		seen[key] = i
	}
	return nil
}
