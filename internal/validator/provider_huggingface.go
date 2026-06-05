package validator

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type huggingfaceValidator struct{}

func (huggingfaceValidator) Name() string { return "huggingface_token" }

func (huggingfaceValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://huggingface.co/api/whoami-v2", nil)
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
			Name string `json:"name"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		if body.Name != "" {
			return ValidationResult{Valid: true, Detail: "user: " + body.Name, State: StateVerified}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("huggingface_token", huggingfaceValidator{})
}
