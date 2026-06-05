package rules

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const RuleSchemaVersion = "1"

//go:embed builtin.yaml
var embeddedRules []byte

type LoadError struct {
	Path string
	Err  error
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e *LoadError) Unwrap() error { return e.Err }

type RuleLoader struct {
	validator *RuleValidator
	compiler  *RuleCompiler
}

func NewRuleLoader() *RuleLoader {
	return &RuleLoader{validator: NewRuleValidator(), compiler: NewRuleCompiler()}
}

func (l *RuleLoader) LoadFromFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{Path: path, Err: err}
	}
	rs, err := l.loadFromBytes(data)
	if err != nil {
		return nil, &LoadError{Path: path, Err: err}
	}
	return rs, nil
}

func (l *RuleLoader) LoadFromDir(dir string) (*RuleSet, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, &LoadError{Path: dir, Err: err}
	}
	merged := &RuleSet{}
	for _, m := range matches {
		rs, err := l.LoadFromFile(m)
		if err != nil {
			return nil, err
		}
		merged.Rules = append(merged.Rules, rs.Rules...)
	}
	if err := l.validator.Validate(*merged); err != nil {
		return nil, &LoadError{Path: dir, Err: err}
	}
	return merged, nil
}

func (l *RuleLoader) loadFromBytes(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	for i, r := range rs.Rules {
		if r.Version != "" && r.Version > RuleSchemaVersion {
			return nil, fmt.Errorf("rule %d (%s): version %q exceeds supported %q", i, r.Name, r.Version, RuleSchemaVersion)
		}
	}
	if err := l.validator.Validate(rs); err != nil {
		return nil, err
	}
	if err := rs.CompileAll(); err != nil {
		return nil, err
	}
	return &rs, nil
}

func LoadDefault() (*RuleSet, error) {
	return NewRuleLoader().loadFromBytes(embeddedRules)
}

func LoadFile(path string) (*RuleSet, error) {
	return NewRuleLoader().LoadFromFile(path)
}

func LoadFromFile(path string) (*RuleSet, error) {
	return NewRuleLoader().LoadFromFile(path)
}

func LoadFromDir(dir string) (*RuleSet, error) {
	return NewRuleLoader().LoadFromDir(dir)
}

func loadFromString(s string) (*RuleSet, error) {
	return NewRuleLoader().loadFromBytes([]byte(s))
}
