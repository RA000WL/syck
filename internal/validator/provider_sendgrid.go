package validator

import (
	"fmt"
	"net/http"
)

type sendgridValidator struct{}

func (sendgridValidator) Name() string { return "sendgrid_api_key" }

func (sendgridValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.sendgrid.com/v3/user/profile", nil)
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
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("sendgrid_api_key", sendgridValidator{})
}
