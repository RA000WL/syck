package rules

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed builtin.yaml
var embeddedRules []byte

func LoadDefault() (*RuleSet, error) {
	return loadYAML(embeddedRules)
}

func LoadFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	return loadYAML(data)
}

func loadYAML(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rules YAML: %w", err)
	}
	if err := rs.CompileAll(); err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	return &rs, nil
}
