package scanner

import (
	"context"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// Scanner is the extension point for all analysis modalities.
// SAST, Secrets, and SCA each implement this interface.
type Scanner interface {
	// Name returns a short identifier ("sast", "secrets", "sca").
	Name() string
	// Accepts returns true if this scanner wants to process the given file.
	Accepts(entry walker.FileEntry) bool
	// Scan analyzes accepted files and returns findings and diagnostics.
	Scan(ctx context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error)
}
