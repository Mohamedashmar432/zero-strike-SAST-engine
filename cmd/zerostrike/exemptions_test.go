package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
	jsonreport "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report/json"
)

func finding(fp, file string, sev core.Severity) core.Finding {
	return core.Finding{ID: fp + file, RuleID: "ZS-PY-001", Severity: sev, Fingerprint: fp, Location: core.Location{File: file, StartLine: 3}}
}

func TestApplyExemptionsMatchesFingerprintAndFileOnly(t *testing.T) {
	ex := []portal.Exemption{{Fingerprint: "fp1", File: "src/db.py", Kind: "false_positive"}}
	in := []core.Finding{
		finding("fp1", "src/db.py", core.SeverityCritical),    // exempted
		finding("fp1", "src/other.py", core.SeverityCritical), // same snippet, other file: counts
		finding("fp2", "src/db.py", core.SeverityHigh),        // other finding, same file: counts
	}
	active, exempted := applyExemptions(in, ex, ".", "/repo")
	if len(active) != 2 || len(exempted) != 1 {
		t.Fatalf("active=%d exempted=%d, want 2/1", len(active), len(exempted))
	}
	if exempted[0].File != "src/db.py" || exempted[0].Kind != "false_positive" || exempted[0].Finding.Fingerprint != "fp1" {
		t.Errorf("exempted = %+v", exempted[0])
	}
}

func TestApplyExemptionsHandlesAbsoluteRootsAndWindowsPaths(t *testing.T) {
	ex := []portal.Exemption{{Fingerprint: "fp1", File: "src/db.py", Kind: "false_positive"}}
	cases := []struct{ file, root, abs string }{
		{"/home/vsts/work/1/s/src/db.py", "/home/vsts/work/1/s", "/home/vsts/work/1/s"}, // Azure Classic, Linux
		{`D:\a\1\s\src\db.py`, `D:\a\1\s`, `D:\a\1\s`},                                  // Azure Classic, Windows
		{"./src/db.py", ".", "/repo"},
		{"src/db.py", ".", "/repo"},
	}
	for _, c := range cases {
		if _, exempted := applyExemptions([]core.Finding{finding("fp1", c.file, core.SeverityCritical)}, ex, c.root, c.abs); len(exempted) != 1 {
			t.Errorf("%q under root %q not matched", c.file, c.root)
		}
	}
}

// TestReportLayoutContract is the contract with every CI gate already pasted into customer YAML:
// they count `^      "Severity": "critical"` (six spaces = a field of a Findings element). An
// accepted exemption must be invisible to that grep, and a counted finding must stay visible. If
// this fails, the report layout changed and those gates would silently count wrong -- do not
// "fix" the test, fix the layout.
func TestReportLayoutContract(t *testing.T) {
	active, exempted := applyExemptions(
		[]core.Finding{finding("fp1", "a.py", core.SeverityCritical), finding("fp2", "b.py", core.SeverityCritical), finding("fp3", "c.py", core.SeverityHigh)},
		[]portal.Exemption{{Fingerprint: "fp1", File: "a.py", Kind: "false_positive"}, {Fingerprint: "fp3", File: "c.py", Kind: "accepted_risk"}},
		".", "/repo",
	)
	rep := &report.Report{Findings: active, AcceptedExemptions: exempted}
	var buf bytes.Buffer
	if err := jsonreport.New().Render(rep, &buf); err != nil {
		t.Fatal(err)
	}
	count := func(sev string) int {
		return len(regexp.MustCompile(`(?m)^      "Severity": "` + sev + `"`).FindAllIndex(buf.Bytes(), -1))
	}
	if got := count("critical"); got != 1 {
		t.Errorf("gate counts %d critical, want 1 (fp2 only)", got)
	}
	if got := count("high"); got != 0 {
		t.Errorf("gate counts %d high, want 0 (fp3 is an accepted risk)", got)
	}
	// ...and the exempted findings are still in the report, for the portal and for a human reader.
	if !bytes.Contains(buf.Bytes(), []byte(`"AcceptedExemptions"`)) || bytes.Count(buf.Bytes(), []byte(`"Fingerprint": "fp1"`)) == 0 {
		t.Error("exempted findings missing from the report")
	}
}

func TestLoadExemptionsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ex.json")
	_ = os.WriteFile(p, []byte(`[{"fingerprint":"fp1","file":"src/db.py","kind":"false_positive"}]`), 0o644)
	ex, err := loadExemptionsFile(p)
	if err != nil || len(ex) != 1 || ex[0].File != "src/db.py" {
		t.Errorf("got %v, %v", ex, err)
	}
	_ = os.WriteFile(p, nil, 0o644)
	if ex, err := loadExemptionsFile(p); err != nil || len(ex) != 0 {
		t.Errorf("empty file: %v, %v", ex, err)
	}
	if _, err := loadExemptionsFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file must be reported, not ignored")
	}
}
