package javascript

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sitterjs "github.com/smacker/go-tree-sitter/javascript"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/parser"
)

// JavaScriptParser parses JavaScript source files using tree-sitter.
type JavaScriptParser struct {
	sitterLang *sitter.Language
}

// New creates a new JavaScriptParser.
func New() *JavaScriptParser {
	return &JavaScriptParser{
		sitterLang: sitterjs.GetLanguage(),
	}
}

func (p *JavaScriptParser) Language() core.Language {
	return core.LangJavaScript
}

func (p *JavaScriptParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter js parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangJavaScript,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
