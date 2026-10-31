package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
	jsonreport "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report/json"
	scascan "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/scanner/sca"
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

// Dependencies must not disturb the gate: nothing inside it may look like a Findings element's
// Severity field (six spaces), and the existing counted/exempted layout must be unchanged.
func TestReportLayoutContractWithDependencies(t *testing.T) {
	active, exempted := applyExemptions(
		[]core.Finding{finding("fp1", "a.py", core.SeverityCritical), finding("fp2", "b.py", core.SeverityHigh)},
		[]portal.Exemption{{Fingerprint: "fp2", File: "b.py", Kind: "accepted_risk"}},
		".", "/repo",
	)
	deps := buildDependencyRefs([]scascan.Dependency{
		{Ecosystem: "PyPI", Package: "requests", Version: "2.31.0", Manifest: "/repo/requirements.txt", Direct: true},
		{Ecosystem: "npm", Package: "lodash", Version: "4.17.21", Manifest: "/repo/web/package-lock.json"},
	}, ".", "/repo")
	rep := &report.Report{Findings: active, AcceptedExemptions: exempted, Dependencies: deps}
	var buf bytes.Buffer
	if err := jsonreport.New().Render(rep, &buf); err != nil {
		t.Fatal(err)
	}
	count := func(sev string) int {
		return len(regexp.MustCompile(`(?m)^      "Severity": "` + sev + `"`).FindAllIndex(buf.Bytes(), -1))
	}
	if count("critical") != 1 || count("high") != 0 {
		t.Errorf("gate counts changed: critical=%d high=%d", count("critical"), count("high"))
	}
	var doc struct{ Dependencies []map[string]any }
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Dependencies) != 2 {
		t.Fatalf("Dependencies has %d entries, want 2", len(doc.Dependencies))
	}
	for _, d := range doc.Dependencies {
		if _, bad := d["Severity"]; bad {
			t.Error("a Dependencies element carries a Severity key")
		}
	}
	if doc.Dependencies[0]["Manifest"] != "requirements.txt" || doc.Dependencies[1]["Manifest"] != "web/package-lock.json" {
		t.Errorf("manifests not repo-relative/sorted: %v", doc.Dependencies)
	}
}

func TestBuildDependencyRefsSortedCappedAndNilAware(t *testing.T) {
	if got := buildDependencyRefs(nil, ".", "/repo"); got != nil {
		t.Errorf("nil inventory = %v, want nil", got)
	}
	if got := buildDependencyRefs([]scascan.Dependency{}, ".", "/repo"); got == nil || len(got) != 0 {
		t.Errorf("empty inventory = %#v, want empty non-nil", got)
	}
	got := buildDependencyRefs([]scascan.Dependency{
		{Ecosystem: "npm", Package: "b", Version: "1", Manifest: "m"},
		{Ecosystem: "PyPI", Package: "z", Version: "1", Manifest: "m"},
		{Ecosystem: "npm", Package: "a", Version: "2", Manifest: "m"},
		{Ecosystem: "npm", Package: "a", Version: "1", Manifest: "m"},
	}, ".", "/repo")
	var order []string
	for _, d := range got {
		order = append(order, d.Ecosystem+"/"+d.Package+"@"+d.Version)
	}
	if want := []string{"PyPI/z@1", "npm/a@1", "npm/a@2", "npm/b@1"}; !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	big := make([]scascan.Dependency, maxDependencyRefs+10)
	for i := range big {
		big[i] = scascan.Dependency{Ecosystem: "npm", Package: fmt.Sprintf("p%06d", i), Version: "1", Manifest: "m"}
	}
	if n := len(buildDependencyRefs(big, ".", "/repo")); n != maxDependencyRefs {
		t.Errorf("cap: got %d, want %d", n, maxDependencyRefs)
	}
}

// Absent when SCA is off, [] when SCA ran over a tree with no manifests.
func TestDependenciesKeyPresence(t *testing.T) {
	render := func(deps []report.DependencyRef) string {
		var buf bytes.Buffer
		if err := jsonreport.New().Render(&report.Report{Dependencies: deps}, &buf); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if out := render(buildDependencyRefs(nil, ".", "/repo")); strings.Contains(out, `"Dependencies"`) {
		t.Error("Dependencies key present although SCA did not run")
	}
	if out := render(buildDependencyRefs([]scascan.Dependency{}, ".", "/repo")); !regexp.MustCompile(`"Dependencies": \[\]`).MatchString(out) {
		t.Errorf("empty inventory must serialise as []:\n%s", out)
	}
}
