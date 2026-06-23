package sca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func makeTestClient(batchURL, vulnBase string) *osvClient {
	return &osvClient{
		http:     &http.Client{Timeout: 5 * time.Second},
		batchURL: batchURL,
		vulnBase: vulnBase,
	}
}

func TestOSVClient_MatchFound(t *testing.T) {
	const advisoryID = "GHSA-1234-5678-abcd"

	vulnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      advisoryID,
			"summary": "Test vulnerability",
			"aliases": []string{"CVE-2024-1234"},
			"database_specific": map[string]string{
				"severity": "HIGH",
			},
			"affected": []map[string]interface{}{
				{
					"ranges": []map[string]interface{}{
						{
							"type": "SEMVER",
							"events": []map[string]string{
								{"introduced": "1.0.0"},
								{"fixed": "1.2.0"},
							},
						},
					},
				},
			},
		})
	}))
	defer vulnSrv.Close()

	batchSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"vulns": []map[string]string{{"id": advisoryID}}},
			},
		})
	}))
	defer batchSrv.Close()

	client := makeTestClient(batchSrv.URL, vulnSrv.URL+"/")
	deps := []Dependency{{Ecosystem: "npm", Package: "lodash", Version: "4.17.20", Direct: true}}

	advisories, err := client.Match(context.Background(), deps)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if len(advisories) == 0 {
		t.Fatal("expected at least one advisory")
	}
	if advisories[0].ID != advisoryID {
		t.Errorf("advisory ID = %q, want %q", advisories[0].ID, advisoryID)
	}
	if advisories[0].Severity != "high" {
		t.Errorf("severity = %q, want high", advisories[0].Severity)
	}
}

func TestOSVClient_NetworkError_WarnMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sc := &SCAScanner{
		client:  makeTestClient(srv.URL, srv.URL+"/"),
		onError: "warn",
	}
	deps := []Dependency{{Ecosystem: "PyPI", Package: "requests", Version: "2.0.0", Direct: true}}

	fs, diags, err := sc.scanDeps(context.Background(), deps)
	if err != nil {
		t.Errorf("expected nil error in warn mode, got: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("expected 0 findings in warn mode on error, got %d", len(fs))
	}
	if len(diags) == 0 {
		t.Error("expected at least one diagnostic in warn mode")
	}
}

func TestOSVClient_NetworkError_FailMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sc := &SCAScanner{
		client:  makeTestClient(srv.URL, srv.URL+"/"),
		onError: "fail",
	}
	deps := []Dependency{{Ecosystem: "PyPI", Package: "requests", Version: "2.0.0", Direct: true}}

	_, _, err := sc.scanDeps(context.Background(), deps)
	if err == nil {
		t.Error("expected non-nil error in fail mode")
	}
}

func TestOSVClient_BatchSplit(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
	}))
	defer srv.Close()

	client := makeTestClient(srv.URL, srv.URL+"/")

	deps := make([]Dependency, 1001)
	for i := range deps {
		deps[i] = Dependency{Ecosystem: "npm", Package: "pkg", Version: "1.0.0"}
	}

	_, err := client.Match(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := int(requestCount.Load()); got != 2 {
		t.Errorf("expected 2 batch requests for 1001 deps, got %d", got)
	}
}
