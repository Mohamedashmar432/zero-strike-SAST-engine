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

// advisoryServer serves one advisory body for any ID and counts the fetches.
func advisoryServer(t *testing.T, hits *int32, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		time.Sleep(delay)
		json.NewEncoder(w).Encode(map[string]any{
			"id":                r.URL.Path[len("/"):],
			"summary":           "test",
			"database_specific": map[string]string{"severity": "HIGH"},
		})
	}))
}

func batchServer(t *testing.T, vulnIDsPerDep [][]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results := make([]map[string]any, 0, len(vulnIDsPerDep))
		for _, ids := range vulnIDsPerDep {
			vulns := make([]map[string]string, 0, len(ids))
			for _, id := range ids {
				vulns = append(vulns, map[string]string{"id": id})
			}
			results = append(results, map[string]any{"vulns": vulns})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
}

// The advisory body for one ID is fetched once per run, however many
// dependencies match it. A shared CVE across a big lockfile used to cost one
// sequential round trip per (dependency, advisory) pair.
func TestMatchFetchesEachAdvisoryOnce(t *testing.T) {
	var hits int32
	vulnSrv := advisoryServer(t, &hits, 0)
	defer vulnSrv.Close()

	// Three dependencies, all matching the same two advisories.
	shared := []string{"GHSA-aaaa", "GHSA-bbbb"}
	batchSrv := batchServer(t, [][]string{shared, shared, shared})
	defer batchSrv.Close()

	client := makeTestClient(batchSrv.URL, vulnSrv.URL+"/")
	deps := []Dependency{
		{Ecosystem: "npm", Package: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Package: "b", Version: "1.0.0"},
		{Ecosystem: "npm", Package: "c", Version: "1.0.0"},
	}

	advisories, err := client.Match(context.Background(), deps)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(advisories) != 6 {
		t.Errorf("advisories = %d, want 6 (one per dependency/advisory pair)", len(advisories))
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("advisory fetches = %d, want 2 (one per unique advisory, not per pair)", got)
	}
}

// Distinct advisories are fetched concurrently: the stage is pure network
// latency, so serial fetching is what turned a large repo's SCA stage into
// minutes of flat-CPU waiting.
func TestMatchFetchesDistinctAdvisoriesConcurrently(t *testing.T) {
	var hits int32
	const delay = 100 * time.Millisecond
	vulnSrv := advisoryServer(t, &hits, delay)
	defer vulnSrv.Close()

	ids := make([]string, 0, 16)
	for i := range 16 {
		ids = append(ids, string(rune('A'+i))+"-advisory")
	}
	batchSrv := batchServer(t, [][]string{ids})
	defer batchSrv.Close()

	client := makeTestClient(batchSrv.URL, vulnSrv.URL+"/")
	deps := []Dependency{{Ecosystem: "npm", Package: "a", Version: "1.0.0"}}

	start := time.Now()
	if _, err := client.Match(context.Background(), deps); err != nil {
		t.Fatalf("Match: %v", err)
	}
	elapsed := time.Since(start)

	if got := atomic.LoadInt32(&hits); got != 16 {
		t.Fatalf("advisory fetches = %d, want 16", got)
	}
	// 16 fetches x 100ms would be 1.6s serially; fetchConcurrency=8 should land
	// near 200ms. Assert well clear of serial without being timing-brittle.
	if elapsed > time.Second {
		t.Errorf("16 advisory fetches took %s — looks serial, not %d-wide", elapsed, fetchConcurrency)
	}
}

// A cancelled context must end the stage instead of silently returning a
// truncated dependency verdict that reads like a clean one.
func TestMatchSurfacesCancellation(t *testing.T) {
	var hits int32
	vulnSrv := advisoryServer(t, &hits, 50*time.Millisecond)
	defer vulnSrv.Close()

	ids := make([]string, 0, 64)
	for i := range 64 {
		ids = append(ids, string(rune('A'+i%26))+string(rune('a'+i/26))+"-adv")
	}
	batchSrv := batchServer(t, [][]string{ids})
	defer batchSrv.Close()

	client := makeTestClient(batchSrv.URL, vulnSrv.URL+"/")
	deps := []Dependency{{Ecosystem: "npm", Package: "a", Version: "1.0.0"}}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := client.Match(ctx, deps)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Match returned nil error after the context expired — a partial SCA result must not look complete")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Match did not return after its context expired")
	}
}
