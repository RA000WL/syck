package validator

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type npmValidator struct{}

func (npmValidator) Name() string { return "npm_token" }

func (npmValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://registry.npmjs.org/-/whoami", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var body struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.Username != "" {
			return ValidationResult{Valid: true, Detail: "user: " + body.Username, State: StateVerified}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("npm_token", npmValidator{})
}
