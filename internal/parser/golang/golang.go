//go:build cgo

package golang

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sittergo "github.com/smacker/go-tree-sitter/golang"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/parser"
)

// GoParser parses Go source files using tree-sitter.
type GoParser struct {
	sitterLang *sitter.Language
}

// New creates a new GoParser.
func New() *GoParser {
	return &GoParser{
		sitterLang: sittergo.GetLanguage(),
	}
}

func (p *GoParser) Language() core.Language {
	return core.LangGo
}

func (p *GoParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter golang parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangGo,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
