//go:build cgo

package java

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sitterjava "github.com/smacker/go-tree-sitter/java"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/parser"
)

// JavaParser parses Java source files using tree-sitter.
type JavaParser struct {
	sitterLang *sitter.Language
}

// New creates a new JavaParser.
func New() *JavaParser {
	return &JavaParser{
		sitterLang: sitterjava.GetLanguage(),
	}
}

func (p *JavaParser) Language() core.Language {
	return core.LangJava
}

func (p *JavaParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter java parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangJava,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
