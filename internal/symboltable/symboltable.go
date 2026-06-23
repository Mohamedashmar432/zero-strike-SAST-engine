package symboltable

import (
	"github.com/google/uuid"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

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

// scopeRange maps a scope to the source range of its defining node.
type scopeRange struct {
	scope Scope
	loc   core.Location
}

// symbolTable is the concrete SymbolTable implementation.
type symbolTable struct {
	symbols     []Symbol
	scopes      []Scope
	scopeRanges []scopeRange
}

func (t *symbolTable) Define(sym Symbol) {
	t.symbols = append(t.symbols, sym)
}

// Resolve walks the scope chain from scopeID up to global and returns the first
// symbol with the given name.
func (t *symbolTable) Resolve(name, scopeID string) (Symbol, bool) {
	for _, sc := range t.scopeChain(scopeID) {
		for _, sym := range t.symbols {
			if sym.Name == name && sym.Scope.ID == sc.ID {
				return sym, true
			}
		}
	}
	return Symbol{}, false
}

// ScopeAt returns the most specific (smallest) scope containing loc.StartLine.
func (t *symbolTable) ScopeAt(loc core.Location) Scope {
	best := Scope{}
	bestSpan := -1
	for _, sr := range t.scopeRanges {
		if loc.StartLine >= sr.loc.StartLine && loc.StartLine <= sr.loc.EndLine {
			span := sr.loc.EndLine - sr.loc.StartLine
			if bestSpan == -1 || span < bestSpan {
				best = sr.scope
				bestSpan = span
			}
		}
	}
	if bestSpan == -1 && len(t.scopes) > 0 {
		return t.scopes[0] // global
	}
	return best
}

func (t *symbolTable) AllSymbols() []Symbol { return t.symbols }

func (t *symbolTable) scopeChain(scopeID string) []Scope {
	var chain []Scope
	current := scopeID
	for current != "" {
		sc := t.findScope(current)
		if sc == nil {
			break
		}
		chain = append(chain, *sc)
		current = sc.ParentID
	}
	return chain
}

func (t *symbolTable) findScope(id string) *Scope {
	for i := range t.scopes {
		if t.scopes[i].ID == id {
			return &t.scopes[i]
		}
	}
	return nil
}

// SymbolBuilder builds a SymbolTable from an IRFile.
type SymbolBuilder struct{}

// NewBuilder creates a new SymbolBuilder.
func NewBuilder() *SymbolBuilder { return &SymbolBuilder{} }

// Build walks the IR tree and extracts scoped symbols.
func (b *SymbolBuilder) Build(irFile *ir.IRFile) SymbolTable {
	table := &symbolTable{}
	globalScope := Scope{ID: uuid.New().String(), ParentID: "", Type: ScopeGlobal}
	table.scopes = append(table.scopes, globalScope)
	if irFile != nil && irFile.Root != nil {
		table.scopeRanges = append(table.scopeRanges, scopeRange{scope: globalScope, loc: irFile.Root.Location})
		b.walkNode(irFile.Root, table, globalScope)
	}
	return table
}

func (b *SymbolBuilder) walkNode(node *ir.IRNode, table *symbolTable, current Scope) {
	if node == nil {
		return
	}

	next := current

	switch node.Kind {
	case ir.NodeKindFunction:
		name := funcName(node)
		if name != "" {
			table.Define(Symbol{Name: name, Kind: SymbolFunction, Location: node.Location, Scope: current})
		}
		// ponytail: Python LEGB excludes class scope from method lookup chain
		parentID := current.ID
		if current.Type == ScopeClass {
			parentID = current.ParentID
		}
		fs := Scope{ID: uuid.New().String(), ParentID: parentID, Type: ScopeFunction}
		table.scopes = append(table.scopes, fs)
		table.scopeRanges = append(table.scopeRanges, scopeRange{scope: fs, loc: node.Location})
		next = fs

	case ir.NodeKindClass:
		name := className(node)
		if name != "" {
			table.Define(Symbol{Name: name, Kind: SymbolClass, Location: node.Location, Scope: current})
		}
		cs := Scope{ID: uuid.New().String(), ParentID: current.ID, Type: ScopeClass}
		table.scopes = append(table.scopes, cs)
		table.scopeRanges = append(table.scopeRanges, scopeRange{scope: cs, loc: node.Location})
		next = cs

	case ir.NodeKindAssignment:
		if len(node.Children) > 0 && node.Children[0].Kind == ir.NodeKindIdentifier {
			c := node.Children[0]
			table.Define(Symbol{Name: c.Text, Kind: SymbolVariable, Location: c.Location, Scope: current})
		}

	case ir.NodeKindImport:
		for _, c := range node.Children {
			if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
				table.Define(Symbol{Name: c.Text, Kind: SymbolImport, Location: c.Location, Scope: current})
			}
		}
	}

	for _, child := range node.Children {
		b.walkNode(child, table, next)
	}
}

func funcName(node *ir.IRNode) string {
	if v, ok := node.Attrs["function_name"].(string); ok && v != "" {
		return v
	}
	// fallback: first identifier child
	for _, c := range node.Children {
		if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
			return c.Text
		}
	}
	return ""
}

func className(node *ir.IRNode) string {
	for _, c := range node.Children {
		if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
			return c.Text
		}
	}
	return ""
}
