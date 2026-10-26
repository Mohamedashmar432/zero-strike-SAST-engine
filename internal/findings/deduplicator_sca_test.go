package findings

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

func TestDependencyFindingsInOneManifestAreNotCollapsed(t *testing.T) {
	// Every dependency finding sits at line 0 of its manifest under one rule ID; deduplicating by
	// location used to keep one advisory per lockfile and drop the rest.
	mk := func(adv string, sev core.Severity) core.Finding {
		return BuildDependencyFinding("ZS-SCA-001", "Vulnerable Dependency", adv,
			DependencyInput{Ecosystem: "npm", Package: "lodash", InstalledVersion: "4.17.15", Manifest: "package.json"},
			[]string{adv}, sev, core.ConfidenceHigh)
	}
	in := []core.Finding{mk("GHSA-a", core.SeverityMedium), mk("GHSA-b", core.SeverityHigh), mk("GHSA-c", core.SeverityCritical)}
	out := NewDeduplicator().Deduplicate(in)
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}

	// A true duplicate (same package+advisory, same manifest) still collapses.
	if got := NewDeduplicator().Deduplicate(append(in, mk("GHSA-a", core.SeverityMedium))); len(got) != 3 {
		t.Errorf("exact duplicate not collapsed: got %d", len(got))
	}
	// The same advisory in a second manifest is a second place to fix.
	other := mk("GHSA-a", core.SeverityMedium)
	other.Location.File = "web/package.json"
	if got := NewDeduplicator().Deduplicate(append(in, other)); len(got) != 4 {
		t.Errorf("second manifest collapsed: got %d, want 4", len(got))
	}
}
