//go:build cgo

package typescript

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	sitterTs "github.com/smacker/go-tree-sitter/typescript/typescript"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser"
)

// TypeScriptParser parses TypeScript source files using tree-sitter.
type TypeScriptParser struct {
	sitterLang *sitter.Language
}

// New creates a new TypeScriptParser.
func New() *TypeScriptParser {
	return &TypeScriptParser{
		sitterLang: sitterTs.GetLanguage(),
	}
}

func (p *TypeScriptParser) Language() core.Language {
	return core.LangTypeScript
}

func (p *TypeScriptParser) Parse(ctx context.Context, source []byte) (*parser.ParseResult, error) {
	sitterParser := sitter.NewParser()
	sitterParser.SetLanguage(p.sitterLang)
	tree, err := sitterParser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter typescript parse: %w", err)
	}
	return &parser.ParseResult{
		Language: core.LangTypeScript,
		Source:   source,
		Tree:     tree,
		RootNode: tree.RootNode(),
	}, nil
}
