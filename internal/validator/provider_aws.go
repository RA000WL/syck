package validator

type awsValidator struct{}

func (awsValidator) Name() string { return "aws_access_key_id" }

func (awsValidator) Validate(secret string) ValidationResult {
	return ValidationResult{Detail: "skipped: needs secret key + STS signing", State: StatePotential}
}

func init() {
	Register("aws_access_key_id", awsValidator{})
}
