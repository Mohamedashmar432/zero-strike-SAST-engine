package rules

import (
	"sync"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

type defaultRegistry struct {
	mu    sync.RWMutex
	rules []*Rule
}

// NewRegistry returns an in-memory Registry implementation.
func NewRegistry() Registry {
	return &defaultRegistry{}
}

func (r *defaultRegistry) Add(rule *Rule) {
	r.mu.Lock()
	r.rules = append(r.rules, rule)
	r.mu.Unlock()
}

func (r *defaultRegistry) ByLanguage(lang core.Language) []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Rule
	for _, rule := range r.rules {
		if rule.Language == lang {
			out = append(out, rule)
		}
	}
	return out
}

func (r *defaultRegistry) ByCategory(category string) []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Rule
	for _, rule := range r.rules {
		if rule.Category == category {
			out = append(out, rule)
		}
	}
	return out
}

func (r *defaultRegistry) ByTag(tag string) []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Rule
	for _, rule := range r.rules {
		for _, t := range rule.Tags {
			if t == tag {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}

func (r *defaultRegistry) All() []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Rule, len(r.rules))
	copy(out, r.rules)
	return out
}
