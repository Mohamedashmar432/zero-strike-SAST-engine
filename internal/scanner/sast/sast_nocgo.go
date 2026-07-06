//go:build !cgo

package sast

import (
	"context"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/cache"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/rules"
	"github.com/zerostrike/scanner/internal/walker"
)

// SASTScanner is a no-op stub for builds without CGo.
// Tree-sitter parsers require CGo (gcc). Install gcc to enable SAST scanning.
type SASTScanner struct{}

// New's signature must stay identical to the cgo build's New (internal/pipeline
// compiles against whichever one the build tag selects). The cache params are
// accepted and ignored, same as allRules/rootPath: this stub never calls Scan
// meaningfully.
func New(_ []*rules.Rule, _ string, _ cache.FindingCache, _ cache.ASTCache) *SASTScanner {
	return &SASTScanner{}
}

func (s *SASTScanner) Name() string { return "sast" }

// Accepts returns false so no files are queued; Scan is still called with an empty slice.
func (s *SASTScanner) Accepts(_ walker.FileEntry) bool { return false }

func (s *SASTScanner) Scan(_ context.Context, _ []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	return nil, nil, nil
}
