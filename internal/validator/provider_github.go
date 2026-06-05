package validator

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type githubValidator struct{}

func (githubValidator) Name() string { return "github_personal_access_token" }

func (githubValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	req.Header.Set("Authorization", "token "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var body struct {
			Login string `json:"login"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		if body.Login != "" {
			return ValidationResult{Valid: true, Detail: "login: " + body.Login, State: StateVerified}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("github_personal_access_token", githubValidator{})
	Register("github_oauth_access_token", githubValidator{})
}
