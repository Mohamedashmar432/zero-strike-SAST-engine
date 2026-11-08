package sca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// An OpenSSF malicious-packages record (MAL-) is Critical and carries the ioc
// marker; an ordinary advisory is untouched.
func TestMaliciousAdvisoryIsCriticalAndMarked(t *testing.T) {
	advisories := map[string]string{"MAL-2025-0001": "MODERATE", "GHSA-aaaa-bbbb-cccc": "LOW"}
	vulnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/"):]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "summary": "test " + id,
			"database_specific": map[string]string{"severity": advisories[id]},
		})
	}))
	defer vulnSrv.Close()
	batchSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"vulns": []map[string]string{{"id": "MAL-2025-0001"}}},
			{"vulns": []map[string]string{{"id": "GHSA-aaaa-bbbb-cccc"}}},
		}})
	}))
	defer batchSrv.Close()

	s := &SCAScanner{client: makeTestClient(batchSrv.URL, vulnSrv.URL+"/"), onError: "fail"}
	deps := []Dependency{
		{Ecosystem: "npm", Package: "evil-pkg", Version: "1.0.0", Manifest: "package-lock.json"},
		{Ecosystem: "npm", Package: "ok-pkg", Version: "1.0.0", Manifest: "package-lock.json"},
	}
	out, _, err := s.scanDeps(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	for _, f := range out {
		switch f.Dependency.Package {
		case "evil-pkg":
			if f.Severity != core.SeverityCritical || f.Metadata["ioc"] != "malicious-package" {
				t.Errorf("malicious package: severity %q metadata %v", f.Severity, f.Metadata)
			}
			if f.Kind != core.FindingKindSCA {
				t.Errorf("kind changed to %q; the finding must stay an SCA finding", f.Kind)
			}
		case "ok-pkg":
			if f.Severity == core.SeverityCritical || f.Metadata["ioc"] != "" {
				t.Errorf("ordinary advisory was marked: severity %q metadata %v", f.Severity, f.Metadata)
			}
		}
	}
}

func TestIsMaliciousAdvisory(t *testing.T) {
	if !isMaliciousAdvisory("MAL-2025-1", nil) || !isMaliciousAdvisory("GHSA-x", []string{"CVE-1", "MAL-9"}) {
		t.Error("MAL- id or alias must match")
	}
	if isMaliciousAdvisory("GHSA-x", []string{"CVE-1", "MALWARE-1"}) {
		t.Error("only the MAL- prefix matches")
	}
}
