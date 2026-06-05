package rules

import (
	"regexp"
	"sync"
)

type RuleCompiler struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
}

func NewRuleCompiler() *RuleCompiler {
	return &RuleCompiler{cache: map[string]*regexp.Regexp{}}
}

func (c *RuleCompiler) Compile(pattern string) (*regexp.Regexp, error) {
	c.mu.RLock()
	if re, ok := c.cache[pattern]; ok {
		c.mu.RUnlock()
		return re, nil
	}
	c.mu.RUnlock()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cache[pattern] = re
	c.mu.Unlock()
	return re, nil
}
