package validator

import (
	"bytes"
	"fmt"
	"net/http"
)

type slackWebhookValidator struct{}

func (slackWebhookValidator) Name() string { return "slack_webhook_url" }

func (slackWebhookValidator) Validate(secret string) ValidationResult {
	payload := []byte(`{"text":"syck validate"}`)
	resp, err := http.Post(secret, "application/json", bytes.NewReader(payload))
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("slack_webhook_url", slackWebhookValidator{})
}
