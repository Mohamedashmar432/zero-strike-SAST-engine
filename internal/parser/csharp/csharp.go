//go:build cgo

package csharp

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sittercsharp "github.com/smacker/go-tree-sitter/csharp"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/parser"
)

// CSharpParser parses C# source files using tree-sitter.
//
// Upstream caveat: the tree-sitter C# grammar shipped with
// github.com/smacker/go-tree-sitter documents itself as incomplete ("it may
// return a partial or wrong AST"). ERROR subtrees are skipped with a warning
// by the IR builder, same as every other language.
type CSharpParser struct {
	sitterLang *sitter.Language
}

// New creates a new CSharpParser.
func New() *CSharpParser {
	return &CSharpParser{
		sitterLang: sittercsharp.GetLanguage(),
	}
}

func (p *CSharpParser) Language() core.Language {
	return core.LangCSharp
}

func (p *CSharpParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter csharp parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangCSharp,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
