package sca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

const (
	defaultBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultVulnBase = "https://api.osv.dev/v1/vulns/"
	batchSize       = 1000
	userAgent       = "zerostrike/0.5.0"
	// Advisory bodies are fetched this many at a time. Each fetch is ~350 ms of
	// pure network latency and no CPU, so this is a latency-hiding number, not a
	// parallelism-for-throughput one; kept modest to stay a polite client of the
	// public OSV API.
	fetchConcurrency = 8
)

type osvClient struct {
	http     *http.Client
	batchURL string // overridable for tests
	vulnBase string // overridable for tests
	// Base wait between retries of a 429/5xx/transport failure (multiplied by the attempt number,
	// overridden by Retry-After). Zero in tests that build the client as a literal.
	retryWait time.Duration

	// Advisory bodies fetched so far, keyed by advisory ID. One GET per unique
	// advisory instead of one per (dependency, advisory) pair: a popular CVE
	// matches dozens of dependencies in a large lockfile, and every one of those
	// used to be a separate sequential round trip. A 4000-file monorepo spent
	// most of its wall clock here -- flat CPU, no output, for as long as the
	// dependency count demanded, which is what "the scan went stale" looked like.
	//
	// ponytail: plain map + mutex, per run, populated by prefetchAdvisories; it
	// deliberately does not persist across runs -- advisory data changes, and a
	// stale cached advisory is a wrong verdict, not a slow one.
	advisories map[string]osvAdvisory
	mu         sync.Mutex
}

func newOSVClient() *osvClient {
	return &osvClient{
		http:       &http.Client{Timeout: 30 * time.Second},
		batchURL:   defaultBatchURL,
		vulnBase:   defaultVulnBase,
		retryWait:  2 * time.Second,
		advisories: map[string]osvAdvisory{},
	}
}

// Advisory is one real vulnerability affecting one dependency. OSV often lists the same
// vulnerability under several IDs (a GHSA and a PYSEC, say); those are merged into one Advisory.
type Advisory struct {
	ID              string // representative ID, stable across runs (see representativeID)
	Summary         string
	Severity        core.Severity
	Confidence      core.Confidence
	VulnerableRange string
	FixedVersion    string
	AliasIDs        []string // representative first, then every other ID and alias, sorted
	Dep             Dependency
	// DetailsUnavailable: OSV listed the advisory for this version but its body could not be
	// fetched. It is still reported -- a dropped advisory reads exactly like a clean dependency.
	DetailsUnavailable bool
}

// Match queries OSV for each dependency and returns matched advisories.
//
// Two phases, deliberately: batch-query every dependency first, then fetch each
// distinct advisory body once, concurrently. Hydrating inline per (dependency,
// advisory) pair the way this used to did one sequential HTTPS round trip per
// pair -- measured at ~350 ms each and 701 pairs for a 3406-dependency monorepo,
// i.e. four minutes of flat-CPU waiting that looked exactly like a hung scanner.
// Deduplicating drops that to 299 fetches, and running them fetchConcurrency-wide
// drops the wall clock by another ~8x.
func (c *osvClient) Match(ctx context.Context, deps []Dependency) ([]Advisory, error) {
	type pair struct {
		dep Dependency
		id  string
	}

	var pairs []pair
	for i := 0; i < len(deps); i += batchSize {
		end := i + batchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[i:end]
		results, err := c.queryBatch(ctx, chunk, nil)
		if err != nil {
			return nil, err
		}
		for j, result := range results {
			if j >= len(chunk) {
				break
			}
			for _, v := range result.Vulns {
				pairs = append(pairs, pair{dep: chunk[j], id: v.ID})
			}
			// OSV pages a query with many advisories; stopping at the first page silently drops
			// the rest of a heavily-advised package (Django, say).
			for token := result.NextPageToken; token != ""; {
				more, err := c.queryBatch(ctx, chunk[j:j+1], []string{token})
				if err != nil {
					return nil, err
				}
				token = ""
				if len(more) > 0 {
					for _, v := range more[0].Vulns {
						pairs = append(pairs, pair{dep: chunk[j], id: v.ID})
					}
					token = more[0].NextPageToken
				}
			}
		}
	}

	ids := make([]string, 0, len(pairs))
	seen := map[string]bool{}
	for _, p := range pairs {
		if !seen[p.id] {
			seen[p.id] = true
			ids = append(ids, p.id)
		}
	}
	if err := c.prefetchAdvisories(ctx, ids); err != nil {
		return nil, err
	}

	// Group per dependency, keeping first-seen order so output is deterministic.
	byDep := map[string][]Advisory{}
	var order []string
	for _, p := range pairs {
		key := depKey(p.dep)
		if _, ok := byDep[key]; !ok {
			order = append(order, key)
			byDep[key] = nil
		}
		// Served from the cache the prefetch just filled. A miss means that advisory's fetch failed
		// even after retries; it is still reported (as high, low confidence) rather than dropped,
		// because a silently missing advisory is indistinguishable from a safe dependency.
		adv, err := c.hydrateVuln(ctx, p.id, p.dep)
		if err != nil {
			adv = Advisory{
				ID:                 p.id,
				Summary:            fmt.Sprintf("%s %s is listed by OSV as affected by %s (advisory details could not be fetched)", p.dep.Package, p.dep.Version, p.id),
				Severity:           core.SeverityHigh,
				Confidence:         core.ConfidenceLow,
				AliasIDs:           []string{p.id},
				Dep:                p.dep,
				DetailsUnavailable: true,
			}
		} else if adv.ID == "" {
			continue // withdrawn
		}
		byDep[key] = append(byDep[key], adv)
	}

	var all []Advisory
	for _, key := range order {
		all = append(all, mergeAliases(byDep[key])...)
	}
	return all, nil
}

func depKey(d Dependency) string {
	return d.Ecosystem + "|" + d.Package + "|" + d.Version + "|" + d.Manifest
}

// mergeAliases collapses advisories that describe the same vulnerability -- OSV returns e.g. both
// GHSA-x and PYSEC-y for one CVE, each naming the other as an alias. Members are linked when any of
// their IDs overlap. The merged advisory takes the highest severity of its members (a GHSA label
// beats a missing one, and never under-reports), and a representative ID chosen deterministically so
// the finding's fingerprint is stable from run to run.
func mergeAliases(advs []Advisory) []Advisory {
	parent := make([]int, len(advs))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	owner := map[string]int{}
	for i, a := range advs {
		for _, id := range append([]string{a.ID}, a.AliasIDs...) {
			if j, ok := owner[id]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[id] = i
			}
		}
	}

	groups := map[int][]Advisory{}
	var roots []int
	for i, a := range advs {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], a)
	}

	out := make([]Advisory, 0, len(roots))
	for _, r := range roots {
		out = append(out, mergeGroup(groups[r]))
	}
	return out
}

func mergeGroup(members []Advisory) Advisory {
	ids := map[string]bool{}
	var listed []string // IDs OSV actually returned for this dependency
	for _, m := range members {
		listed = append(listed, m.ID)
		ids[m.ID] = true
		for _, a := range m.AliasIDs {
			ids[a] = true
		}
	}
	rep := representativeID(listed)

	merged := Advisory{ID: rep, Dep: members[0].Dep, DetailsUnavailable: true}
	for _, m := range members {
		if !m.DetailsUnavailable {
			merged.DetailsUnavailable = false
		}
		if severityRank(m.Severity) > severityRank(merged.Severity) ||
			(m.Severity == merged.Severity && confidenceRank(m.Confidence) > confidenceRank(merged.Confidence)) {
			merged.Severity, merged.Confidence = m.Severity, m.Confidence
		}
	}
	// Text and ranges from the representative when it has them, else the first member that does.
	ordered := append([]Advisory{}, members...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID == rep && ordered[j].ID != rep })
	for _, m := range ordered {
		if merged.Summary == "" && m.Summary != "" && !m.DetailsUnavailable {
			merged.Summary = m.Summary
		}
		if merged.FixedVersion == "" && merged.VulnerableRange == "" {
			merged.VulnerableRange, merged.FixedVersion = m.VulnerableRange, m.FixedVersion
		}
	}
	if merged.Summary == "" {
		merged.Summary = ordered[0].Summary
	}

	delete(ids, rep)
	rest := make([]string, 0, len(ids))
	for id := range ids {
		rest = append(rest, id)
	}
	sort.Strings(rest)
	merged.AliasIDs = append([]string{rep}, rest...)
	return merged
}

// representativeID picks the ID a merged advisory is known by: a GHSA when OSV returned one (it
// carries the reviewed severity label), else the lexicographically smallest. Deterministic, so the
// finding fingerprint built from it survives re-scans and portal triage keeps applying.
func representativeID(ids []string) string {
	sorted := append([]string{}, ids...)
	sort.Strings(sorted)
	for _, id := range sorted {
		if strings.HasPrefix(id, "GHSA-") {
			return id
		}
	}
	return sorted[0]
}

func severityRank(s core.Severity) int {
	switch s {
	case core.SeverityCritical:
		return 5
	case core.SeverityHigh:
		return 4
	case core.SeverityMedium:
		return 3
	case core.SeverityLow:
		return 2
	case core.SeverityInfo:
		return 1
	}
	return 0
}

func confidenceRank(c core.Confidence) int {
	switch c {
	case core.ConfidenceHigh:
		return 3
	case core.ConfidenceMedium:
		return 2
	case core.ConfidenceLow:
		return 1
	}
	return 0
}

// prefetchAdvisories fills the advisory cache for ids, fetchConcurrency requests
// at a time. Individual failures are left to hydrateVuln's best-effort path; a
// cancelled context aborts, because every remaining fetch would fail too and a
// silently truncated dependency verdict reads like a clean one.
func (c *osvClient) prefetchAdvisories(ctx context.Context, ids []string) error {
	work := make(chan string)
	var wg sync.WaitGroup
	for range min(fetchConcurrency, len(ids)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				if ctx.Err() != nil {
					return
				}
				_, _ = c.fetchAdvisory(ctx, id)
			}
		}()
	}
	for _, id := range ids {
		// select, not a bare send: the workers return the moment the context is
		// cancelled, so a bare send would block forever with nobody receiving --
		// the same shape of deadlock this whole change exists to remove.
		select {
		case work <- id:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	return nil
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

// queryBatch returns OSV's per-dependency advisory IDs for one chunk, positionally
// aligned with deps. Fetching the advisory bodies is Match's job, so that the
// distinct set can be fetched once and in parallel. pageTokens, when given, is aligned
// with deps and continues a paged query.
func (c *osvClient) queryBatch(ctx context.Context, deps []Dependency, pageTokens []string) ([]osvBatchResult, error) {
	queries := make([]osvQuery, len(deps))
	for i, d := range deps {
		queries[i] = osvQuery{
			Package: osvPackage{Name: d.Package, Ecosystem: d.Ecosystem},
			Version: d.Version,
		}
		if i < len(pageTokens) {
			queries[i].PageToken = pageTokens[i]
		}
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal batch request: %w", err)
	}

	respData, err := c.doPost(ctx, c.batchURL, body)
	if err != nil {
		return nil, err
	}

	var batchResp osvBatchResponse
	if err := json.Unmarshal(respData, &batchResp); err != nil {
		return nil, fmt.Errorf("osv: unmarshal batch response: %w", err)
	}

	return batchResp.Results, nil
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRange struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced"`
		Fixed        string `json:"fixed"`
		LastAffected string `json:"last_affected"`
	} `json:"events"`
}

type osvAdvisory struct {
	ID               string        `json:"id"`
	Summary          string        `json:"summary"`
	Aliases          []string      `json:"aliases"`
	Withdrawn        string        `json:"withdrawn"`
	Severity         []osvSeverity `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Severity []osvSeverity `json:"severity"`
		Ranges   []osvRange    `json:"ranges"`
	} `json:"affected"`
}

// hydrateVuln resolves one advisory for one dependency. A withdrawn advisory comes back with an
// empty ID (and no error) so the caller skips it.
func (c *osvClient) hydrateVuln(ctx context.Context, id string, dep Dependency) (Advisory, error) {
	raw, err := c.fetchAdvisory(ctx, id)
	if err != nil {
		return Advisory{}, err
	}
	if raw.Withdrawn != "" {
		return Advisory{}, nil
	}

	sev, conf := parseSeverity(raw)
	allIDs := append([]string{raw.ID}, raw.Aliases...)
	vulnRange, fixedVer := extractRanges(raw, dep)

	return Advisory{
		ID:              raw.ID,
		Summary:         raw.Summary,
		Severity:        sev,
		Confidence:      conf,
		VulnerableRange: vulnRange,
		FixedVersion:    fixedVer,
		AliasIDs:        allIDs,
		Dep:             dep,
	}, nil
}

// fetchAdvisory returns the advisory body for id, fetching it at most once per run.
func (c *osvClient) fetchAdvisory(ctx context.Context, id string) (osvAdvisory, error) {
	c.mu.Lock()
	cached, ok := c.advisories[id]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}

	respData, err := c.doGet(ctx, c.vulnBase+id)
	if err != nil {
		return osvAdvisory{}, err
	}
	var raw osvAdvisory
	if err := json.Unmarshal(respData, &raw); err != nil {
		return osvAdvisory{}, fmt.Errorf("osv: unmarshal vuln %s: %w", id, err)
	}

	c.mu.Lock()
	// Lazily created: tests (and any other caller) build osvClient as a struct
	// literal, so the map is not always set up by newOSVClient.
	if c.advisories == nil {
		c.advisories = map[string]osvAdvisory{}
	}
	c.advisories[id] = raw
	c.mu.Unlock()
	return raw, nil
}

// parseSeverity rates one advisory. Order: the curated label (GitHub's reviewed severity), then a
// CVSS v3 base score computed from the vector, then -- for advisories that carry neither, or only a
// CVSS v2/v4 vector -- medium at reduced confidence. The fallback used to apply to every vector-only
// advisory, so a 9.8 that happened to come from PyPI's or Go's database read as "medium" and passed
// a gate set to high.
func parseSeverity(raw osvAdvisory) (core.Severity, core.Confidence) {
	switch strings.ToUpper(raw.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return core.SeverityCritical, core.ConfidenceHigh
	case "HIGH":
		return core.SeverityHigh, core.ConfidenceHigh
	case "MODERATE", "MEDIUM":
		return core.SeverityMedium, core.ConfidenceMedium
	case "LOW":
		return core.SeverityLow, core.ConfidenceLow
	}
	vectors := append([]osvSeverity{}, raw.Severity...)
	for _, aff := range raw.Affected {
		vectors = append(vectors, aff.Severity...)
	}
	best, found := -1.0, false
	for _, v := range vectors {
		if v.Type != "CVSS_V3" {
			continue
		}
		if score, ok := cvss3BaseScore(v.Score); ok && score > best {
			best, found = score, true
		}
	}
	if found {
		return severityFromScore(best), core.ConfidenceMedium
	}
	if len(vectors) > 0 {
		return core.SeverityMedium, core.ConfidenceMedium
	}
	return core.SeverityMedium, core.ConfidenceLow
}

// severityFromScore maps a CVSS base score to the qualitative rating CVSS v3 defines.
func severityFromScore(score float64) core.Severity {
	switch {
	case score >= 9.0:
		return core.SeverityCritical
	case score >= 7.0:
		return core.SeverityHigh
	case score >= 4.0:
		return core.SeverityMedium
	case score > 0:
		return core.SeverityLow
	}
	return core.SeverityInfo
}

// cvss3BaseScore computes a CVSS v3.0/v3.1 base score from its vector string, per the FIRST
// specification. ok is false for anything that is not a complete, valid v3 base vector.
func cvss3BaseScore(vector string) (score float64, ok bool) {
	parts := strings.Split(vector, "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, found := strings.Cut(p, ":")
		if !found {
			return 0, false
		}
		m[k] = v
	}
	weight := func(key string, table map[string]float64) (float64, bool) {
		w, found := table[m[key]]
		return w, found
	}
	changed := m["S"] == "C"
	if m["S"] != "U" && !changed {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	prw, ok3 := weight("PR", pr)
	ui, ok4 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok5 := weight("C", cia)
	i, ok6 := weight("I", cia)
	a, ok7 := weight("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * prw * ui
	if changed {
		return roundUp1(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp1(math.Min(impact+exploitability, 10)), true
}

// roundUp1 is CVSS v3.1's Roundup: the smallest one-decimal number >= x, computed on integers so
// floating-point noise (4.000000001) does not push a score up a step.
func roundUp1(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// extractRanges returns the affected range that contains dep's installed version, from the
// advisory entry for dep's own package. An advisory often covers several release lines (Django
// 3.2.x and 4.0.x are separate ranges with separate fixes) and sometimes several packages; reading
// the first range regardless used to name a "fixed in" version that does not apply to the installed
// one. Falls back to the first range of the matching package when no range brackets the version.
func extractRanges(raw osvAdvisory, dep Dependency) (vulnRange, fixedVer string) {
	var firstRange, firstFixed string
	for _, aff := range raw.Affected {
		if aff.Package.Name != "" && normalizePackageName(dep.Ecosystem, aff.Package.Name) != normalizePackageName(dep.Ecosystem, dep.Package) {
			continue
		}
		for _, r := range aff.Ranges {
			if r.Type == "GIT" {
				continue
			}
			intro := ""
			for _, ev := range r.Events {
				switch {
				case ev.Introduced != "":
					intro = ev.Introduced
				case ev.Fixed != "" || ev.LastAffected != "":
					desc, fixed := describeRange(intro, ev.Fixed, ev.LastAffected)
					if firstRange == "" {
						firstRange, firstFixed = desc, fixed
					}
					if dep.Version != "" && versionInRange(dep.Version, intro, ev.Fixed, ev.LastAffected) {
						return desc, fixed
					}
					intro = ""
				}
			}
			if intro != "" { // open-ended: introduced with no fix yet
				desc, _ := describeRange(intro, "", "")
				if firstRange == "" {
					firstRange = desc
				}
				if dep.Version != "" && versionInRange(dep.Version, intro, "", "") {
					return desc, ""
				}
			}
		}
	}
	return firstRange, firstFixed
}

func describeRange(intro, fixed, lastAffected string) (string, string) {
	if intro == "0" {
		intro = ""
	}
	var parts []string
	if intro != "" {
		parts = append(parts, ">="+intro)
	}
	if fixed != "" {
		parts = append(parts, "<"+fixed)
	} else if lastAffected != "" {
		parts = append(parts, "<="+lastAffected)
	}
	return strings.Join(parts, ", "), fixed
}

func versionInRange(v, intro, fixed, lastAffected string) bool {
	if intro != "" && intro != "0" && compareVersions(v, intro) < 0 {
		return false
	}
	if fixed != "" {
		return compareVersions(v, fixed) < 0
	}
	if lastAffected != "" {
		return compareVersions(v, lastAffected) <= 0
	}
	return true
}

// compareVersions orders two version strings well enough to pick a range: it splits each into runs
// of digits and runs of letters and compares run by run (digits numerically). A trailing letter run
// on the longer one marks a pre-release ("1.0.0rc1" < "1.0.0"); a trailing number marks a later
// patch. It is only used to choose which reported range to display -- OSV itself decides whether
// the version is affected.
func compareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		if c := compareToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ta) == len(tb):
		return 0
	case len(ta) > len(tb):
		if isDigits(ta[len(tb)]) {
			return 1
		}
		return -1
	default:
		if isDigits(tb[len(ta)]) {
			return -1
		}
		return 1
	}
}

func versionTokens(v string) []string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var out []string
	cur := strings.Builder{}
	digit := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if !digit {
				flush()
			}
			digit = true
			cur.WriteRune(r)
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			if digit {
				flush()
			}
			digit = false
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func compareToken(a, b string) int {
	ad, bd := isDigits(a), isDigits(b)
	switch {
	case ad && bd:
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			if len(a) < len(b) {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	case ad:
		return 1 // a number outranks a pre-release tag at the same position
	case bd:
		return -1
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizePackageName folds the spellings an ecosystem treats as the same package (PEP 503 for
// PyPI: case-insensitive, runs of -_. equal), so an advisory's entry for "pyyaml" matches "PyYAML".
func normalizePackageName(ecosystem, name string) string {
	name = strings.ToLower(name)
	if ecosystem == "PyPI" {
		name = pep503Re.ReplaceAllString(name, "-")
	}
	return name
}

var pep503Re = regexp.MustCompile(`[-_.]+`)

func (c *osvClient) doPost(ctx context.Context, url string, body []byte) ([]byte, error) {
	return c.doRequest(ctx, http.MethodPost, url, body)
}

func (c *osvClient) doGet(ctx context.Context, url string) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, url, nil)
}

const maxAttempts = 3

// doRequest retries transport errors, 429 and 5xx up to maxAttempts times, waiting retryWait x
// attempt between tries (or the server's Retry-After, capped at 30s). OSV rate-limits busy clients;
// giving up on the first 429 used to skip the whole dependency scan with only a warning, which a CI
// gate reads as "no vulnerable dependencies".
func (c *osvClient) doRequest(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("osv: %w", ctx.Err())
			case <-time.After(c.backoff(attempt, lastErr)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("osv: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("osv: %w", ctx.Err())
			}
			lastErr = fmt.Errorf("osv: request failed: %w", err)
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = &retryableStatus{code: resp.StatusCode, url: url, retryAfter: resp.Header.Get("Retry-After")}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv: HTTP %d for %s", resp.StatusCode, url)
		}
		if readErr != nil {
			return nil, fmt.Errorf("osv: read response: %w", readErr)
		}
		return data, nil
	}
	return nil, fmt.Errorf("osv: giving up after %d attempts: %w", maxAttempts, lastErr)
}

type retryableStatus struct {
	code       int
	url        string
	retryAfter string
}

func (e *retryableStatus) Error() string { return fmt.Sprintf("osv: HTTP %d for %s", e.code, e.url) }

func (c *osvClient) backoff(attempt int, lastErr error) time.Duration {
	var rs *retryableStatus
	if errors.As(lastErr, &rs) && rs.retryAfter != "" && c.retryWait > 0 {
		if secs, err := strconv.Atoi(rs.retryAfter); err == nil && secs > 0 {
			return min(time.Duration(secs)*time.Second, 30*time.Second)
		}
	}
	return c.retryWait * time.Duration(attempt-1)
}
