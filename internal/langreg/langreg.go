// Package langreg is the single registration point for scannable languages.
// Each language package (internal/parser/<lang>) registers an Entry from an
// init() in its register.go; consumers dispatch via Get instead of hardcoding
// per-language switch statements.
//
// The package itself is pure Go (it only references the ir.Builder interface,
// not any cgo-gated implementation), so it compiles under CGO_ENABLED=0 —
// the registry is simply empty there because the cgo-gated register.go files
// are excluded from the build.
package langreg

import (
	"sort"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// Entry describes one scannable language: how to build IR for it and where
// its embedded rules live.
type Entry struct {
	Language   core.Language
	NewBuilder func() ir.Builder
	RuleDir    string // rule directory inside internal/rules' embedded FS, e.g. "data/python"
}

var entries = map[core.Language]Entry{}

// Register adds (or replaces) the Entry for a language. It is intended to be
// called from language packages' init() functions.
func Register(e Entry) { entries[e.Language] = e }

// Get returns the Entry for a language, or false if none is registered.
func Get(lang core.Language) (Entry, bool) {
	e, ok := entries[lang]
	return e, ok
}

// NoParsersMessage returns a diagnosis when registered is 0, or "" otherwise.
// A CGO_ENABLED=0 build excludes every cgo-gated register.go, leaving this
// registry empty and SAST detection a silent no-op.
//
// Every consumer must surface this rather than proceeding quietly, because
// the failure looks like a result: a scan reports a near-empty findings list
// as a clean repo (QA Sprint 23 — a stale no-CGo binary scored ~1% detection
// across 5 known-vulnerable repos before anyone questioned the build), and a
// benchmark scores a ~0% SAST recall as a real measurement (the committed
// baseline.json advertised 22.64% recall for ten sprints on exactly this).
func NoParsersMessage(registered int) string {
	if registered > 0 {
		return ""
	}
	return "no language parsers registered — this binary was built with CGO_ENABLED=0, so SAST detection is disabled. Rebuild with CGO_ENABLED=1 and a C compiler on PATH."
}

// All returns every registered Entry in stable (language-name) order.
func All() []Entry {
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Language < out[j].Language })
	return out
}
