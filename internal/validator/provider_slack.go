package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type slackValidator struct{}

func (slackValidator) Name() string { return "slack_token" }

func (slackValidator) Validate(secret string) ValidationResult {
	data := []byte("token=" + secret)
	req, err := http.NewRequest("POST", "https://slack.com/api/auth.test", bytes.NewReader(data))
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	defer resp.Body.Close()
	var body struct {
		OK   bool   `json:"ok"`
		User string `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.OK {
		if body.User != "" {
			return ValidationResult{Valid: true, Detail: "user: " + body.User, State: StateVerified}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("slack_token", slackValidator{})
}
