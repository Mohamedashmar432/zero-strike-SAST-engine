//go:build cgo

package html

import (
	"context"
	"fmt"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser"
	sitter "github.com/smacker/go-tree-sitter"
	sitterhtml "github.com/smacker/go-tree-sitter/html"
)

// HTMLParser parses HTML source files using tree-sitter.
type HTMLParser struct {
	sitterLang *sitter.Language
}

// New creates a new HTMLParser.
func New() *HTMLParser {
	return &HTMLParser{
		sitterLang: sitterhtml.GetLanguage(),
	}
}

func (p *HTMLParser) Language() core.Language {
	return core.LangHTML
}

func (p *HTMLParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangHTML,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
