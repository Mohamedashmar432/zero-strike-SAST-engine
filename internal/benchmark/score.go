package benchmark

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/pipeline"
)

// ScoreEvent is one TP/FP/FN outcome, tagged with the rule ID and modality
// it applies to, so Summary can aggregate per-rule/per-modality stats.
type ScoreEvent struct {
	RuleID  string
	Kind    core.FindingKind
	Outcome string // "tp" | "fp" | "fn"
}

// CaseResult is the scored outcome for one manifest case.
type CaseResult struct {
	Dir    string
	File   string
	TP     int
	FP     int
	FN     int
	Notes  []string // human-readable mismatch detail, for the report
	Events []ScoreEvent
}

// RuleStats is precision-relevant TP/FP for one rule ID.
type RuleStats struct {
	TP, FP int
}

// LangStats is recall-relevant TP/FN for one language.
type LangStats struct {
	TP, FN int
}

// ModalityStats is TP/FP/FN for one Finding.Kind ("sast"/"secret"/"sca"/"config").
type ModalityStats struct {
	TP, FP, FN int
}

// Summary aggregates every case's score into overall and per-dimension numbers.
type Summary struct {
	TP, FP, FN int
	ByRule     map[string]*RuleStats
	ByLanguage map[string]*LangStats
	ByModality map[string]*ModalityStats
	Cases      []CaseResult
}

func (s *Summary) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

func (s *Summary) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

func newSummary() *Summary {
	return &Summary{
		ByRule:     make(map[string]*RuleStats),
		ByLanguage: make(map[string]*LangStats),
		ByModality: make(map[string]*ModalityStats),
	}
}

// ScoreCorpus runs the full pipeline (all scanners enabled) against every
// corpus subdirectory and scores the results against each manifest.
// enableGraphs opts into CFG/DFG-based path-sensitive taint reporting; it's
// additive (see internal/analyzer.New) and shouldn't change which findings
// fire, only whether TaintContext.Path is populated.
func ScoreCorpus(ctx context.Context, dirs []CorpusDir, enableGraphs bool) (*Summary, error) {
	summary := newSummary()

	for _, dir := range dirs {
		cfg := pipeline.ScanConfig{
			RootPath:              dir.Dir,
			EnableSecrets:         true,
			EnableSCA:             true,
			EnableFrameworkChecks: true,
			EnableGraphs:          enableGraphs,
			SCAOnError:            "warn",
		}
		pipe, err := pipeline.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("corpus %s: pipeline.New: %w", dir.Name, err)
		}
		result, err := pipe.Run(ctx)
		if err != nil {
			return nil, fmt.Errorf("corpus %s: pipeline.Run: %w", dir.Name, err)
		}

		findingsByFile := make(map[string][]core.Finding)
		for _, f := range result.Findings {
			rel, err := filepath.Rel(dir.Dir, f.Location.File)
			if err != nil {
				continue
			}
			rel = filepath.ToSlash(rel)
			findingsByFile[rel] = append(findingsByFile[rel], f)
		}

		for _, c := range dir.Manifest.Cases {
			cr := scoreCase(dir.Name, c, findingsByFile[c.File])
			summary.TP += cr.TP
			summary.FP += cr.FP
			summary.FN += cr.FN
			summary.Cases = append(summary.Cases, cr)

			lang := c.Language
			if lang != "" {
				ls := summary.ByLanguage[lang]
				if ls == nil {
					ls = &LangStats{}
					summary.ByLanguage[lang] = ls
				}
				ls.TP += cr.TP
				ls.FN += cr.FN
			}

			for _, ev := range cr.Events {
				rs := summary.ByRule[ev.RuleID]
				if rs == nil {
					rs = &RuleStats{}
					summary.ByRule[ev.RuleID] = rs
				}
				ms := summary.ByModality[string(ev.Kind)]
				if ms == nil {
					ms = &ModalityStats{}
					summary.ByModality[string(ev.Kind)] = ms
				}
				switch ev.Outcome {
				case "tp":
					rs.TP++
					ms.TP++
				case "fp":
					rs.FP++
					ms.FP++
				case "fn":
					ms.FN++
				}
			}
		}
	}

	return summary, nil
}

// scoreCase matches one case's expectations against the findings that
// landed on its file, marking consumed findings so a single finding can't
// satisfy two expectations, then treats anything left over as a false
// positive.
func scoreCase(dirName string, c Case, fileFindings []core.Finding) CaseResult {
	cr := CaseResult{Dir: dirName, File: c.File}
	consumed := make([]bool, len(fileFindings))

	for _, exp := range c.Expect {
		minCount := exp.MinCount
		if minCount < 1 {
			minCount = 1
		}
		matched := 0
		for i, f := range fileFindings {
			if consumed[i] {
				continue
			}
			if !expectationMatches(exp, f) {
				continue
			}
			consumed[i] = true
			matched++
		}
		if matched >= minCount {
			cr.TP++
			cr.Events = append(cr.Events, ScoreEvent{RuleID: expectationLabel(exp), Kind: expectationKind(exp), Outcome: "tp"})
		} else {
			cr.FN++
			cr.Notes = append(cr.Notes, fmt.Sprintf("expected %s (min_count=%d), matched %d", expectationLabel(exp), minCount, matched))
			cr.Events = append(cr.Events, ScoreEvent{RuleID: expectationLabel(exp), Kind: expectationKind(exp), Outcome: "fn"})
		}
	}

	for i, f := range fileFindings {
		if consumed[i] {
			continue
		}
		cr.FP++
		cr.Notes = append(cr.Notes, fmt.Sprintf("unexpected finding %s", f.RuleID))
		cr.Events = append(cr.Events, ScoreEvent{RuleID: f.RuleID, Kind: f.Kind, Outcome: "fp"})
	}

	return cr
}

func expectationMatches(exp Expectation, f core.Finding) bool {
	if exp.Dependency != nil {
		return f.Kind == core.FindingKindSCA && f.Dependency != nil &&
			strings.EqualFold(f.Dependency.Package, exp.Dependency.Package) &&
			strings.EqualFold(f.Dependency.Ecosystem, exp.Dependency.Ecosystem)
	}
	return f.RuleID == exp.RuleID
}

func expectationLabel(exp Expectation) string {
	if exp.Dependency != nil {
		return fmt.Sprintf("dependency %s/%s", exp.Dependency.Ecosystem, exp.Dependency.Package)
	}
	return exp.RuleID
}

// expectationKind infers the Finding.Kind an expectation maps to, for
// per-modality aggregation on the FN path (where there is no actual
// finding to read Kind from).
func expectationKind(exp Expectation) core.FindingKind {
	switch {
	case exp.Dependency != nil:
		return core.FindingKindSCA
	case strings.HasPrefix(exp.RuleID, "ZS-SEC-"):
		return core.FindingKindSecret
	case strings.HasPrefix(exp.RuleID, "ZS-CFG-"):
		return core.FindingKindConfig
	default:
		return core.FindingKindSAST
	}
}
