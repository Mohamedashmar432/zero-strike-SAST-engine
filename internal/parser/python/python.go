package python

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sitterpython "github.com/smacker/go-tree-sitter/python"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/parser"
)

// PythonParser parses Python source files using tree-sitter.
type PythonParser struct {
	sitterLang *sitter.Language
}

// New creates a new PythonParser.
func New() *PythonParser {
	return &PythonParser{
		sitterLang: sitterpython.GetLanguage(),
	}
}

func (p *PythonParser) Language() core.Language {
	return core.LangPython
}

func (p *PythonParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangPython,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
