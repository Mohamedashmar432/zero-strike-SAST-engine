package engine

import (
	"context"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/rules"
)

// MatchResult is a single rule match against an IR node.
type MatchResult struct {
	Rule     *rules.Rule
	NodeID   string
	Captures map[string]string // named captures from the match pattern
}

// Project provides cross-file context for multi-file analysis.
// In Sprint 1 this is nil for all matches.
type Project struct {
	Root string
}

// MatchContext bundles everything the engine needs to match rules.
type MatchContext struct {
	Rules   []*rules.Rule
	File    *analyzer.AnalysisResult
	Project *Project // nil in Sprint 1
}

// Engine matches rules against an AnalysisResult.
type Engine interface {
	Match(ctx context.Context, mc *MatchContext) ([]MatchResult, error)
}
