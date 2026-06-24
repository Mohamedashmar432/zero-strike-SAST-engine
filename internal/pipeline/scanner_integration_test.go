//go:build cgo

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

	pipe, err := pipeline.New(cfg)
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	result, err := pipe.Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Error("expected at least 1 file scanned, got 0")
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least 1 finding from python testdata, got 0")
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

	pipe, err := pipeline.New(cfg)
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	result, err := pipe.Run(context.Background())
	if err != nil {
		t.Fatalf("scan of empty dir failed: %v", err)
	}

	if result.FilesScanned != 0 {
		t.Errorf("expected 0 files scanned in empty dir, got %d", result.FilesScanned)
	}
}

// TestScanPipeline_Workers_ConcurrentMatchesSequential verifies the concurrent
// scanner path (WorkerCount>1) produces the same result as sequential (WorkerCount=1).
func TestScanPipeline_Workers_ConcurrentMatchesSequential(t *testing.T) {
	dir := t.TempDir()

	run := func(workers int) *pipeline.ScanResult {
		pipe, err := pipeline.New(pipeline.ScanConfig{
			RootPath:    dir,
			WorkerCount: workers,
			NoCache:     true,
		})
		if err != nil {
			t.Fatalf("pipeline.New(workers=%d): %v", workers, err)
		}
		result, err := pipe.Run(context.Background())
		if err != nil {
			t.Fatalf("Run(workers=%d): %v", workers, err)
		}
		return result
	}

	seq := run(1)
	conc := run(4)

	if seq.FilesScanned != conc.FilesScanned {
		t.Errorf("FilesScanned: sequential=%d concurrent=%d", seq.FilesScanned, conc.FilesScanned)
	}
	if len(seq.Findings) != len(conc.Findings) {
		t.Errorf("Findings: sequential=%d concurrent=%d", len(seq.Findings), len(conc.Findings))
	}
}
