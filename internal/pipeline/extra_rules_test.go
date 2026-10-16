//go:build cgo

package pipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/pipeline"
)

const extraRuleYAML = `id: ZS-CUSTOM-001
name: Custom Marker Call
version: "1.0.0"
language: python
category: dangerous-functions
severity: high
confidence: high
lifecycle: released
description: |
  Flags calls to custom_danger.
message: "custom_danger call"
match:
  kind: call
  callee: custom_danger
fix_suggestion: "Do not call custom_danger."
rationale: |
  custom_danger is forbidden by local policy.
`

func scanExtra(t *testing.T, root, extraDir string) (map[string]bool, error) {
	t.Helper()
	pipe, err := pipeline.New(pipeline.ScanConfig{RootPath: root, ExtraRulesDir: extraDir, WorkerCount: 1, NoCache: true})
	if err != nil {
		return nil, err
	}
	res, err := pipe.Run(context.Background())
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.RuleID] = true
	}
	return ids, nil
}

func extraSample(t *testing.T) string {
	root := t.TempDir()
	src := "import os\nx = eval(input())\ncustom_danger(x)\n"
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeExtra(t *testing.T, name, body string) string {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExtraRules_FireAlongsideEmbedded(t *testing.T) {
	ids, err := scanExtra(t, extraSample(t), writeExtra(t, "ZS-CUSTOM-001.yaml", extraRuleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !ids["ZS-CUSTOM-001"] {
		t.Errorf("extra rule did not fire: %v", ids)
	}
	if !ids["ZS-PY-001"] {
		t.Errorf("embedded rule ZS-PY-001 did not fire with --extra-rules set: %v", ids)
	}
}

func TestExtraRules_InvalidRuleErrorsNamingFile(t *testing.T) {
	bad := strings.Replace(extraRuleYAML, "severity: high", "severity: bogus", 1)
	_, err := scanExtra(t, extraSample(t), writeExtra(t, "bad-rule.yaml", bad))
	if err == nil {
		t.Fatal("expected error for invalid extra rule")
	}
	if !strings.Contains(err.Error(), "bad-rule.yaml") && !strings.Contains(err.Error(), "ZS-CUSTOM-001") {
		t.Errorf("error should identify the offending rule/file: %v", err)
	}
}

func TestExtraRules_DuplicateOfEmbeddedErrors(t *testing.T) {
	dup := strings.Replace(extraRuleYAML, "ZS-CUSTOM-001", "ZS-PY-001", 1)
	_, err := scanExtra(t, extraSample(t), writeExtra(t, "dup.yaml", dup))
	if err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("expected duplicate-ID error, got %v", err)
	}
}
