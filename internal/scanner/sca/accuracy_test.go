package sca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// fakeOSV serves querybatch from batch (ids per query, in order) and advisory bodies from vulns.
// A vulns entry of nil makes that advisory's GET fail with 500.
func fakeOSV(t *testing.T, batch func(q osvQuery) osvBatchResult, vulns map[string]map[string]any) *osvClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req osvBatchRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			var resp osvBatchResponse
			for _, q := range req.Queries {
				resp.Results = append(resp.Results, batch(q))
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/vulns/")
		body, ok := vulns[id]
		if !ok || body == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return makeTestClient(srv.URL+"/querybatch", srv.URL+"/vulns/")
}

func ids(list ...string) osvBatchResult {
	var r osvBatchResult
	for _, id := range list {
		r.Vulns = append(r.Vulns, struct {
			ID string `json:"id"`
		}{ID: id})
	}
	return r
}

func TestManyAdvisoriesInOneManifestAreAllReported(t *testing.T) {
	// The bug that hid almost every dependency CVE: all advisories of one manifest collapsed into one.
	vulns := map[string]map[string]any{}
	var all []string
	for _, id := range []string{"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"} {
		all = append(all, id)
		vulns[id] = map[string]any{"id": id, "database_specific": map[string]string{"severity": "HIGH"}}
	}
	vulns["GHSA-cccc"]["database_specific"] = map[string]string{"severity": "CRITICAL"}
	c := fakeOSV(t, func(osvQuery) osvBatchResult { return ids(all...) }, vulns)
	sc := &SCAScanner{client: c, onError: "warn"}

	fs, _, err := sc.scanDeps(context.Background(), []Dependency{{Ecosystem: "npm", Package: "x", Version: "1.0.0", Manifest: "package.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3 (one per advisory)", len(fs))
	}
	var crit int
	for _, f := range fs {
		if f.Severity == core.SeverityCritical {
			crit++
		}
	}
	if crit != 1 {
		t.Errorf("critical findings = %d, want 1", crit)
	}
}

func TestAliasedAdvisoriesMergeIntoOneFindingWithStableIDAndHighestSeverity(t *testing.T) {
	vulns := map[string]map[string]any{
		// PyPI's own record: CVSS vector only (9.8), no label.
		"PYSEC-2020-1": {"id": "PYSEC-2020-1", "aliases": []string{"CVE-2020-1", "GHSA-zzzz"},
			"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
		// GitHub's record of the same CVE, labelled HIGH.
		"GHSA-zzzz": {"id": "GHSA-zzzz", "aliases": []string{"CVE-2020-1"}, "summary": "RCE in yaml.load",
			"database_specific": map[string]string{"severity": "HIGH"}},
	}
	c := fakeOSV(t, func(osvQuery) osvBatchResult { return ids("PYSEC-2020-1", "GHSA-zzzz") }, vulns)

	advs, err := c.Match(context.Background(), []Dependency{{Ecosystem: "PyPI", Package: "PyYAML", Version: "5.3"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1 merged", len(advs))
	}
	a := advs[0]
	if a.ID != "GHSA-zzzz" || a.AliasIDs[0] != "GHSA-zzzz" {
		t.Errorf("representative = %q (%v), want the GHSA", a.ID, a.AliasIDs)
	}
	if a.Severity != core.SeverityCritical {
		t.Errorf("severity = %q, want critical (max of HIGH label and 9.8 vector)", a.Severity)
	}
	if a.Summary != "RCE in yaml.load" {
		t.Errorf("summary = %q", a.Summary)
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		got, ok := cvss3BaseScore(vec)
		if !ok || got != want {
			t.Errorf("%s = %v (ok=%v), want %v", vec, got, ok, want)
		}
	}
	for _, bad := range []string{"", "AV:N/AC:L", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N"} {
		if _, ok := cvss3BaseScore(bad); ok {
			t.Errorf("%q accepted as a v3 vector", bad)
		}
	}
}

func TestVectorOnlyAdvisoryIsRatedFromItsScoreNotDefaultedToMedium(t *testing.T) {
	raw := osvAdvisory{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}
	if sev, _ := parseSeverity(raw); sev != core.SeverityCritical {
		t.Errorf("severity = %q, want critical", sev)
	}
}

func TestFixedVersionComesFromTheRangeHoldingTheInstalledVersion(t *testing.T) {
	var raw osvAdvisory
	_ = json.Unmarshal([]byte(`{"affected":[
	  {"package":{"name":"other-pkg","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]},
	  {"package":{"name":"django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[
	    {"introduced":"3.2"},{"fixed":"3.2.14"},{"introduced":"4.0"},{"fixed":"4.0.6"}]}]}]}`), &raw)

	r, fixed := extractRanges(raw, Dependency{Ecosystem: "PyPI", Package: "Django", Version: "4.0.1"})
	if fixed != "4.0.6" || r != ">=4.0, <4.0.6" {
		t.Errorf("4.0.1 -> %q fixed %q, want >=4.0, <4.0.6 / 4.0.6", r, fixed)
	}
	if _, fixed := extractRanges(raw, Dependency{Ecosystem: "PyPI", Package: "Django", Version: "3.2.0"}); fixed != "3.2.14" {
		t.Errorf("3.2.0 fixed = %q, want 3.2.14", fixed)
	}
}

func TestCompareVersions(t *testing.T) {
	less := [][2]string{{"1.2.0", "1.10.0"}, {"1.0.0rc1", "1.0.0"}, {"1.0.0-beta", "1.0.0"}, {"3.2", "3.2.14"}, {"v1.9", "1.10"}}
	for _, p := range less {
		if compareVersions(p[0], p[1]) >= 0 || compareVersions(p[1], p[0]) <= 0 {
			t.Errorf("want %s < %s", p[0], p[1])
		}
	}
	if compareVersions("2.0.0", "2.0.0") != 0 {
		t.Error("equal versions should compare 0")
	}
}

func TestUnfetchableAdvisoryIsReportedNotDropped(t *testing.T) {
	c := fakeOSV(t, func(osvQuery) osvBatchResult { return ids("GHSA-gone") }, map[string]map[string]any{"GHSA-gone": nil})
	advs, err := c.Match(context.Background(), []Dependency{{Ecosystem: "npm", Package: "x", Version: "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || !advs[0].DetailsUnavailable || advs[0].Severity != core.SeverityHigh {
		t.Fatalf("got %+v, want one high advisory marked DetailsUnavailable", advs)
	}
}

func TestWithdrawnAdvisoryIsSkipped(t *testing.T) {
	vulns := map[string]map[string]any{
		"GHSA-old": {"id": "GHSA-old", "withdrawn": "2024-01-01T00:00:00Z"},
		"GHSA-new": {"id": "GHSA-new"},
	}
	c := fakeOSV(t, func(osvQuery) osvBatchResult { return ids("GHSA-old", "GHSA-new") }, vulns)
	advs, _ := c.Match(context.Background(), []Dependency{{Ecosystem: "npm", Package: "x", Version: "1.0.0"}})
	if len(advs) != 1 || advs[0].ID != "GHSA-new" {
		t.Fatalf("got %+v, want only GHSA-new", advs)
	}
}

func TestPagedQueryIsFollowed(t *testing.T) {
	vulns := map[string]map[string]any{"GHSA-p1": {"id": "GHSA-p1"}, "GHSA-p2": {"id": "GHSA-p2"}}
	c := fakeOSV(t, func(q osvQuery) osvBatchResult {
		if q.PageToken == "" {
			r := ids("GHSA-p1")
			r.NextPageToken = "page-2"
			return r
		}
		return ids("GHSA-p2")
	}, vulns)
	advs, err := c.Match(context.Background(), []Dependency{{Ecosystem: "PyPI", Package: "django", Version: "3.2.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 {
		t.Fatalf("got %d advisories, want 2 across both pages", len(advs))
	}
}

func TestRateLimitIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{}}})
	}))
	defer srv.Close()
	c := makeTestClient(srv.URL, srv.URL+"/")
	if _, err := c.Match(context.Background(), []Dependency{{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}); err != nil {
		t.Fatalf("429 then 200 should succeed, got %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
}

func TestPackageJSONIsIgnoredNextToALockfile(t *testing.T) {
	dir := t.TempDir()
	// The range floor (4.17.15) is vulnerable; the locked version (4.17.21) is not.
	write := func(name, body string) walker.FileEntry {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return walker.FileEntry{Path: p}
	}
	files := []walker.FileEntry{
		write("package.json", `{"dependencies":{"lodash":"^4.17.15"}}`),
		write("package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`),
	}
	var queried []string
	c := fakeOSV(t, func(q osvQuery) osvBatchResult {
		queried = append(queried, q.Package.Name+"@"+q.Version)
		return osvBatchResult{}
	}, nil)
	sc := &SCAScanner{client: c, onError: "warn"}
	if _, _, err := sc.Scan(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if len(queried) != 1 || queried[0] != "lodash@4.17.21" {
		t.Errorf("queried %v, want only the locked lodash@4.17.21", queried)
	}
}
