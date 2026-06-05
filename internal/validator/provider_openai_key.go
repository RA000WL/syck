package validator

import "strings"

type openaiKeyValidator struct{}

func (openaiKeyValidator) Name() string { return "openai_key" }

func (openaiKeyValidator) Validate(secret string) ValidationResult {
	if !strings.HasPrefix(secret, "sk-") {
		return ValidationResult{Detail: "not an OpenAI key (missing sk- prefix)", State: StatePotential}
	}
	v := openaiValidator{}
	return v.Validate(secret)
}

func init() {
	Register("openai_key", openaiKeyValidator{})
}
