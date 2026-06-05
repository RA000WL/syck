package validator

import (
	"fmt"
	"net/http"
)

type stripeValidator struct{}

func (stripeValidator) Name() string { return "stripe_secret_key" }

func (stripeValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
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
	Register("stripe_secret_key", stripeValidator{})
}
