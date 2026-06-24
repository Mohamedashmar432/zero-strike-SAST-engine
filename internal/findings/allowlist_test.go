package findings_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

func makeTestFinding(ruleID, fingerprint, file string) core.Finding {
	return core.Finding{
		RuleID:      ruleID,
		Fingerprint: fingerprint,
		Location:    core.Location{File: file},
	}
}

func TestSuppressedByRuleID(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{ID: "ZS-SEC-003"}},
	}
	f := makeTestFinding("ZS-SEC-003", "fp1", "src/config.py")
	if !al.Suppressed(f) {
		t.Fatal("expected finding to be suppressed by rule ID")
	}
}

func TestSuppressedByFingerprint(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{Fingerprint: "abc123def456"}},
	}
	f := makeTestFinding("ZS-SEC-001", "abc123def456", "src/keys.py")
	if !al.Suppressed(f) {
		t.Fatal("expected finding to be suppressed by fingerprint")
	}
}

func TestSuppressedByIDAndPath(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{ID: "ZS-SEC-004", Path: "tests/*"}},
	}
	inTests := makeTestFinding("ZS-SEC-004", "fp2", "tests/fixtures.py")
	notInTests := makeTestFinding("ZS-SEC-004", "fp3", "src/app.py")

	if !al.Suppressed(inTests) {
		t.Fatal("expected finding in tests/ to be suppressed")
	}
	if al.Suppressed(notInTests) {
		t.Fatal("expected finding outside tests/ to not be suppressed")
	}
}

func TestNotSuppressed_WrongRule(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{ID: "ZS-SEC-003"}},
	}
	f := makeTestFinding("ZS-SEC-001", "fp4", "src/keys.py")
	if al.Suppressed(f) {
		t.Fatal("expected non-matching rule ID to not suppress")
	}
}

func TestNotSuppressed_WrongFingerprint(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{Fingerprint: "aaaaaaaaaaaa"}},
	}
	f := makeTestFinding("ZS-SEC-001", "bbbbbbbbbbbb", "src/keys.py")
	if al.Suppressed(f) {
		t.Fatal("expected non-matching fingerprint to not suppress")
	}
}

func TestAllowList_DoubleStarGlob_Match(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{ID: "ZS-PY-001", Path: "src/**/*.py"}},
	}
	f := makeTestFinding("ZS-PY-001", "fp5", "src/auth/login.py")
	if !al.Suppressed(f) {
		t.Fatal("expected src/auth/login.py to match src/**/*.py")
	}
}

func TestAllowList_DoubleStarGlob_NoMatch(t *testing.T) {
	al := &findings.AllowList{
		Suppressions: []findings.Suppression{{ID: "ZS-PY-001", Path: "src/**/*.py"}},
	}
	f := makeTestFinding("ZS-PY-001", "fp6", "other/app.py")
	if al.Suppressed(f) {
		t.Fatal("expected other/app.py to NOT match src/**/*.py")
	}
}

func TestLoadAllowList(t *testing.T) {
	yaml := `version: "1"
suppressions:
  - id: ZS-SEC-003
    reason: "test values"
  - fingerprint: "abc123"
    reason: "known FP"
  - id: ZS-SEC-004
    path: "tests/*"
    reason: "fixtures"
`
	tmp := filepath.Join(t.TempDir(), ".zs-allow.yaml")
	if err := os.WriteFile(tmp, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	al, err := findings.LoadAllowList(tmp)
	if err != nil {
		t.Fatalf("LoadAllowList: %v", err)
	}
	if al.Version != "1" {
		t.Errorf("version: got %q want %q", al.Version, "1")
	}
	if len(al.Suppressions) != 3 {
		t.Errorf("suppressions: got %d want 3", len(al.Suppressions))
	}
	if al.Suppressions[1].Fingerprint != "abc123" {
		t.Errorf("fingerprint: got %q want %q", al.Suppressions[1].Fingerprint, "abc123")
	}
}
