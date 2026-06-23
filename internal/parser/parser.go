package parser

import (
	"context"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/zerostrike/scanner/internal/core"
)

// ParseResult holds the raw tree-sitter output for a single file.
type ParseResult struct {
	Language core.Language
	Source   []byte
	Tree     *sitter.Tree
	RootNode *sitter.Node
}

// Parser parses source files for a specific language.
type Parser interface {
	Language() core.Language
	Parse(ctx context.Context, source []byte) (*ParseResult, error)
}
