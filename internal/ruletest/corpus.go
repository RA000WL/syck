package ruletest

func LoadPositive(ruleName string) []string {
	return GeneratePositive(ruleName)
}

func LoadNegative() []string {
	return GenerateNegative()
}
