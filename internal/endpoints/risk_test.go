package endpoints

import "testing"

func TestRiskScore(t *testing.T) {
	cases := []struct {
		path string
		want int
	}{
		// FP safety
		{"/blog/tokenization", 0},
		{"/docs/oauth-guide", 0},
		{"/api/v1/health", 0},

		// IDOR-prone
		{"/api/v1/users/123", 3},
		{"/api/v1/accounts/me", 3},
		{"/api/v1/profile", 2},

		// Auth
		{"/api/v1/auth/login", 4},

		// Admin
		{"/admin", 4},
		{"/admin/login", 6},
		{"/admin/users/1", 8},

		// Internal/debug
		{"/internal/foo", 5},
		{"/actuator", 6},
		{"/actuator/env", 8},
		{"/actuator/configprops", 8},

		// Password reset
		{"/reset-password", 5},

		// Template paths
		{"/api/v1/users/{id}", 4},

		// GraphQL
		{"/api/graphql", 2},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := ComputeRiskScore(tc.path)
			if got != tc.want {
				t.Errorf("ComputeRiskScore(%q) = %d, want %d", tc.path, got, tc.want)
			}
		})
	}
}
