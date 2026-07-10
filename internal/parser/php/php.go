//go:build cgo

package php

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sitterphp "github.com/smacker/go-tree-sitter/php"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser"
)

// PHPParser parses PHP source files using tree-sitter.
type PHPParser struct {
	sitterLang *sitter.Language
}

// New creates a new PHPParser.
func New() *PHPParser {
	return &PHPParser{
		sitterLang: sitterphp.GetLanguage(),
	}
}

func (p *PHPParser) Language() core.Language {
	return core.LangPHP
}

func (p *PHPParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter php parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangPHP,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
