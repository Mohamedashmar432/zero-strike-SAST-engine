package symboltable

import "github.com/zerostrike/scanner/internal/core"

// ScopeType identifies the kind of lexical scope.
type ScopeType string

const (
	ScopeGlobal   ScopeType = "global"
	ScopeFunction ScopeType = "function"
	ScopeClass    ScopeType = "class"
	ScopeBlock    ScopeType = "block"
)

// Scope represents a lexical scope in the source program.
type Scope struct {
	ID       string
	ParentID string
	Type     ScopeType
}

// SymbolKind identifies what a symbol represents.
type SymbolKind string

const (
	SymbolVariable  SymbolKind = "variable"
	SymbolFunction  SymbolKind = "function"
	SymbolClass     SymbolKind = "class"
	SymbolImport    SymbolKind = "import"
	SymbolParameter SymbolKind = "parameter"
)

// Symbol represents a named entity in source code.
type Symbol struct {
	Name     string
	Kind     SymbolKind
	Type     string // inferred type, empty if unknown
	Location core.Location
	Scope    Scope
}

// SymbolTable provides scoped symbol lookup for a single file.
type SymbolTable interface {
	Define(sym Symbol)
	Resolve(name string, scopeID string) (Symbol, bool)
	ScopeAt(loc core.Location) Scope
	AllSymbols() []Symbol
}

// Builder constructs a SymbolTable from an IR file.
type Builder interface {
	Build(root interface{}) (SymbolTable, error)
}
