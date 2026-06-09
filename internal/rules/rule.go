package rules

import (
	"regexp"
)

type Rule struct {
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description,omitempty"`
	Severity         string   `yaml:"severity"`
	Pattern          string   `yaml:"pattern"`
	Tags             []string `yaml:"tags,omitempty"`
	EntropyThreshold float64  `yaml:"entropy_threshold,omitempty"`
	ContextKeywords  []string `yaml:"context_keywords,omitempty"`
	RequiresContext  bool     `yaml:"requires_context,omitempty"`
	Verify           bool     `yaml:"verify,omitempty"`
	Version          string   `yaml:"version,omitempty"`
	MultiLine        bool     `yaml:"multi_line,omitempty"`
	compiled         *regexp.Regexp
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

func (r *Rule) Compile() error {
	compiled, err := regexp.Compile(r.Pattern)
	if err != nil {
		return err
	}
	r.compiled = compiled
	return nil
}

func (r *Rule) Match(s string) []int {
	if r.compiled == nil {
		return nil
	}
	m := r.compiled.FindStringIndex(s)
	if m == nil {
		return nil
	}
	return m
}

func (r *Rule) MatchAll(s string) [][]int {
	if r.compiled == nil {
		return nil
	}
	return r.compiled.FindAllStringIndex(s, -1)
}

func (r *Rule) Compiled() *regexp.Regexp {
	return r.compiled
}

func (rs *RuleSet) CompileAll() error {
	for i := range rs.Rules {
		if err := rs.Rules[i].Compile(); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RuleSet) Len() int {
	return len(rs.Rules)
}
