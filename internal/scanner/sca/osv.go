package sca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zerostrike/scanner/internal/core"
)

const (
	defaultBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultVulnBase = "https://api.osv.dev/v1/vulns/"
	batchSize       = 1000
	userAgent       = "zerostrike/0.5.0"
)

type osvClient struct {
	http     *http.Client
	batchURL string // overridable for tests
	vulnBase string // overridable for tests
}

func newOSVClient() *osvClient {
	return &osvClient{
		http:     &http.Client{Timeout: 30 * time.Second},
		batchURL: defaultBatchURL,
		vulnBase: defaultVulnBase,
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
func (c *osvClient) Match(ctx context.Context, deps []Dependency) ([]Advisory, error) {
	var all []Advisory
	for i := 0; i < len(deps); i += batchSize {
		end := i + batchSize
		if end > len(deps) {
			end = len(deps)
		}
		matched, err := c.queryBatch(ctx, deps[i:end])
		if err != nil {
			return nil, err
		}
		all = append(all, matched...)
	}
	return all, nil
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

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

func (c *osvClient) queryBatch(ctx context.Context, deps []Dependency) ([]Advisory, error) {
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

	var advisories []Advisory
	for i, result := range batchResp.Results {
		if i >= len(deps) {
			break
		}
		for _, v := range result.Vulns {
			adv, err := c.hydrateVuln(ctx, v.ID, deps[i])
			if err != nil {
				continue // best-effort
			}
			advisories = append(advisories, adv)
		}
	}
	return advisories, nil
}

type osvAdvisory struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
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
				Fixed       string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (c *osvClient) hydrateVuln(ctx context.Context, id string, dep Dependency) (Advisory, error) {
	respData, err := c.doGet(ctx, c.vulnBase+id)
	if err != nil {
		return Advisory{}, err
	}

	var raw osvAdvisory
	if err := json.Unmarshal(respData, &raw); err != nil {
		return Advisory{}, fmt.Errorf("osv: unmarshal vuln %s: %w", id, err)
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
