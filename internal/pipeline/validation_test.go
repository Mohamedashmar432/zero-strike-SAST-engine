package pipeline_test

import (
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/pipeline"
)

// TestPipelineNew_UnregisteredLanguageFailsFast verifies that requesting a
// language with no registered parser fails at pipeline construction time,
// not per file mid-scan. This test runs under both CGo and no-CGo builds:
// "nonexistent-lang" is never registered in either.
func TestPipelineNew_UnregisteredLanguageFailsFast(t *testing.T) {
	_, err := pipeline.New(pipeline.ScanConfig{
		RootPath:  t.TempDir(),
		Languages: []core.Language{"nonexistent-lang"},
	})
	if err == nil {
		t.Fatal("expected pipeline.New to fail for an unregistered language, got nil error")
	}
	if !strings.Contains(err.Error(), "nonexistent-lang") {
		t.Errorf("expected error to name the offending language, got: %v", err)
	}
}
