package validator

import (
	"bytes"
	"fmt"
	"net/http"
)

type anthropicValidator struct{}

func (anthropicValidator) Name() string { return "anthropic_api_key" }

func (anthropicValidator) Validate(secret string) ValidationResult {
	body := []byte(`{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", secret)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 || resp.StatusCode == 400 {
		return ValidationResult{Valid: true, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StateVerified}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("anthropic_api_key", anthropicValidator{})
}
