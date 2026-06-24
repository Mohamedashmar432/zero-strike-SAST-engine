//go:build cgo

package parser

import "github.com/zerostrike/scanner/internal/core"

// Registry maps languages to their parsers.
type Registry struct {
	parsers map[core.Language]Parser
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{parsers: make(map[core.Language]Parser)}
}

// Register adds a parser for a language.
func (r *Registry) Register(lang core.Language, p Parser) {
	r.parsers[lang] = p
}

// Get returns the parser for a language, or false if not registered.
func (r *Registry) Get(lang core.Language) (Parser, bool) {
	p, ok := r.parsers[lang]
	return p, ok
}
