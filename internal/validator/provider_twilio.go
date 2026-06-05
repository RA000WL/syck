package validator

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

type twilioValidator struct{}

func (twilioValidator) Name() string { return "twilio_api_key" }

func (twilioValidator) Validate(secret string) ValidationResult {
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	req, err := http.NewRequest("GET", "https://api.twilio.com/2010-04-01/Accounts.json", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	req.Header.Set("Authorization", "Basic "+encoded)
	resp, err := httpDo(req)
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
	Register("twilio_api_key", twilioValidator{})
}
