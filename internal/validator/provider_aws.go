package validator

import "strings"

type awsValidator struct{}

func (awsValidator) Name() string { return "aws_access_key_id" }

func (v awsValidator) Validate(secret string) ValidationResult {
	if len(secret) < 16 || !strings.HasPrefix(secret, "AKIA") {
		return ValidationResult{Detail: "invalid AWS key format", State: StatePotential}
	}
	return ValidationResult{
		Valid:  true,
		Detail: "requires secret key for STS signing",
		State:  StateLikely,
	}
}

func init() {
	Register("aws_access_key_id", awsValidator{})
}
