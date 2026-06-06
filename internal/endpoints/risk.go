package endpoints

import "regexp"

type riskRule struct {
	Pattern           *regexp.Regexp
	Weight            int
	RequiresAPIPrefix bool
	Group             string
}

var riskScoringRules = []riskRule{
	// IDOR-prone
	{regexp.MustCompile(`(?i)/users?/(\d+|me|self)\b`), 3, true, "idor"},
	{regexp.MustCompile(`(?i)/accounts?/(\d+|me|self)\b`), 3, true, "idor"},
	{regexp.MustCompile(`(?i)/(?:me|self|profile)(?:/|$|\?)`), 2, true, "idor"},

	// Admin / privileged
	{regexp.MustCompile(`(?i)/admin(?:/|$|\?)`), 4, false, "admin"},
	{regexp.MustCompile(`(?i)/admin/users?/`), 5, false, "admin"},
	{regexp.MustCompile(`(?i)/admin/(?:settings|config|login|panel)`), 6, false, "admin"},

	// Internal / debug
	{regexp.MustCompile(`(?i)/(?:internal|debug|private)(?:/|$|\?)`), 5, false, "internal"},
	{regexp.MustCompile(`(?i)/(?:actuator|metrics|prometheus)(?:/|$|\?)`), 6, false, "actuator"},
	{regexp.MustCompile(`(?i)/actuator/env`), 8, false, "actuator"},
	{regexp.MustCompile(`(?i)/actuator/configprops`), 8, false, "actuator"},
	{regexp.MustCompile(`(?i)/health`), 0, false, "health"},

	// Auth / tokens
	{regexp.MustCompile(`(?i)/(?:auth|oauth|token|api-?key|secret)s?(?:/|$|\?)`), 4, true, "auth"},
	{regexp.MustCompile(`(?i)/(?:reset|forgot)-?password`), 5, false, "reset"},

	// Template paths
	{regexp.MustCompile(`(?i)/(?:api/v\d+/)?users?/\{[^}]+\}`), 4, true, "template"},
	{regexp.MustCompile(`(?i)/(?:api/v\d+/)?accounts?/\{[^}]+\}`), 4, true, "template"},

	// GraphQL endpoints
	{regexp.MustCompile(`(?i)/(?:api/)?graphql(?:/v\d+)?`), 2, false, "graphql"},
}

var apiLikeRe = regexp.MustCompile(`(?i)^(?:/api|/v\d+|/internal|/admin|/auth|/actuator)`)

// ComputeRiskScore returns a 0-10 risk score for an endpoint path.
// Rules are grouped by category; within each group the highest weight wins.
// Scores sum across groups. RequiresAPIPrefix prevents FPs on
// common paths like /blog/tokenization.
func ComputeRiskScore(path string) int {
	groupScores := make(map[string]int)
	for _, r := range riskScoringRules {
		if !r.Pattern.MatchString(path) {
			continue
		}
		if r.RequiresAPIPrefix && !apiLikeRe.MatchString(path) {
			continue
		}
		if r.Weight > groupScores[r.Group] {
			groupScores[r.Group] = r.Weight
		}
	}
	score := 0
	for _, w := range groupScores {
		score += w
	}
	if score > 10 {
		score = 10
	}
	return score
}
