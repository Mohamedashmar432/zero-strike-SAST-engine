package sca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		advisories: map[string]osvAdvisory{},
	}
}

// Advisory is the resolved vulnerability data for a single advisory ID.
type Advisory struct {
	ID              string
	Summary         string
	Severity        core.Severity
	Confidence      core.Confidence
	VulnerableRange string
	FixedVersion    string
	AliasIDs        []string // all IDs: primary + aliases (CVE, GHSA, etc.)
	Dep             Dependency
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
		results, err := c.queryBatch(ctx, chunk)
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

	var all []Advisory
	for _, p := range pairs {
		// Served from the cache the prefetch just filled; a miss means that one
		// advisory's fetch failed, and it stays best-effort -- one unreachable
		// advisory must not sink the whole dependency verdict.
		adv, err := c.hydrateVuln(ctx, p.id, p.dep)
		if err != nil {
			continue
		}
		all = append(all, adv)
	}
	return all, nil
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
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

// queryBatch returns OSV's per-dependency advisory IDs for one chunk, positionally
// aligned with deps. Fetching the advisory bodies is Match's job, so that the
// distinct set can be fetched once and in parallel.
func (c *osvClient) queryBatch(ctx context.Context, deps []Dependency) ([]osvBatchResult, error) {
	queries := make([]osvQuery, len(deps))
	for i, d := range deps {
		queries[i] = osvQuery{
			Package: osvPackage{Name: d.Package, Ecosystem: d.Ecosystem},
			Version: d.Version,
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

type osvAdvisory struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (c *osvClient) hydrateVuln(ctx context.Context, id string, dep Dependency) (Advisory, error) {
	raw, err := c.fetchAdvisory(ctx, id)
	if err != nil {
		return Advisory{}, err
	}

	sev, conf := parseSeverity(raw)
	allIDs := append([]string{raw.ID}, raw.Aliases...)
	vulnRange, fixedVer := extractRanges(raw)

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
	if len(raw.Severity) > 0 {
		return core.SeverityMedium, core.ConfidenceMedium
	}
	return core.SeverityMedium, core.ConfidenceLow
}

func extractRanges(raw osvAdvisory) (vulnRange, fixedVer string) {
	for _, aff := range raw.Affected {
		for _, r := range aff.Ranges {
			var intro, fixed string
			for _, ev := range r.Events {
				if ev.Introduced != "" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
			}
			if intro == "0" {
				intro = ""
			}
			if intro != "" && fixed != "" {
				return ">=" + intro + ", <" + fixed, fixed
			} else if fixed != "" {
				return "<" + fixed, fixed
			} else if intro != "" {
				return ">=" + intro, ""
			}
		}
	}
	return "", ""
}

func (c *osvClient) doPost(ctx context.Context, url string, body []byte) ([]byte, error) {
	return c.doRequest(ctx, http.MethodPost, url, body)
}

func (c *osvClient) doGet(ctx context.Context, url string) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, url, nil)
}

func (c *osvClient) doRequest(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	for attempt := 1; attempt <= 2; attempt++ {
		var bodyReader *bytes.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("osv: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("osv: request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 && attempt == 1 {
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv: HTTP %d for %s", resp.StatusCode, url)
		}

		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, fmt.Errorf("osv: read response: %w", err)
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("osv: request failed after retries")
}
