package pipeline_test

import (
	"context"
	"testing"

	"github.com/zerostrike/scanner/internal/pipeline"
)

func TestScanPipeline_Python(t *testing.T) {
	cfg := pipeline.ScanConfig{
		RootPath:    "../../testdata/python",
		WorkerCount: 1,
		NoCache:     true,
	}

	result, err := pipeline.New(cfg).Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Error("expected at least 1 file scanned, got 0")
	}

	t.Logf("Scanned: %d files, Skipped: %d files", result.FilesScanned, result.FilesSkipped)
	t.Logf("Diagnostics: %d", len(result.Diagnostics))
	t.Logf("Findings: %d", len(result.Findings))
}

func TestScanPipeline_EmptyDir(t *testing.T) {
	cfg := pipeline.ScanConfig{
		RootPath:    t.TempDir(),
		WorkerCount: 1,
		NoCache:     true,
	}

	result, err := pipeline.New(cfg).Run(context.Background())
	if err != nil {
		t.Fatalf("scan of empty dir failed: %v", err)
	}

	if result.FilesScanned != 0 {
		t.Errorf("expected 0 files scanned in empty dir, got %d", result.FilesScanned)
	}
}
