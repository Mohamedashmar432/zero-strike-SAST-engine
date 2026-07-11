// SPDX-License-Identifier: Apache-2.0

// Package portal is the ZeroStrike engine's client for the zero-strike-portal
// backend's scanner-facing REST contract: register a scan, upload its
// reports, and report pipeline failure. Stdlib net/http only, mirroring
// internal/scanner/sca's OSV client — a single-purpose client, not a
// general-purpose SDK.
package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// Client talks to one zero-strike-portal server on behalf of one project
// token.
type Client struct {
	http    *http.Client
	baseURL string
	token   string
}

// New returns a Client for baseURL, authenticating every request with token
// as a Bearer credential.
func New(baseURL, token string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 60 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
	}
}

// HTTPError is returned for any non-2xx portal response. Callers that need
// to distinguish an auth failure from a server/network problem should
// errors.As into this type and check StatusCode.
type HTTPError struct {
	StatusCode int
	URL        string
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("portal: HTTP %d from %s: %s", e.StatusCode, e.URL, e.Body)
}

// CreateScanRequest is the body of POST /api/v1/scans. The token alone
// resolves the project server-side, so no project ID is sent here.
type CreateScanRequest struct {
	ScannerVersion string `json:"scanner_version"`
	Hostname       string `json:"hostname,omitempty"`
	GitCommit      string `json:"git_commit,omitempty"`
	Branch         string `json:"branch,omitempty"`
	ScanLabel      string `json:"scan_label,omitempty"`
}

// CreateScanResponse is the body of a successful POST /api/v1/scans response.
type CreateScanResponse struct {
	ScanID      string `json:"scan_id"`
	Status      string `json:"status"`
	ProjectID   string `json:"project_id"`
	ProjectName string `json:"project_name"`
}

// CreateScan registers a new scan with the portal and returns the
// server-assigned scan ID used in all subsequent calls. A 401 (invalid,
// expired, or revoked token) comes back as an *HTTPError with
// StatusCode 401 — callers must fail fast on it without running the pipeline.
func (c *Client) CreateScan(ctx context.Context, req CreateScanRequest) (CreateScanResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CreateScanResponse{}, fmt.Errorf("portal: marshal create-scan request: %w", err)
	}
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/scans", body, "application/json")
	if err != nil {
		return CreateScanResponse{}, err
	}
	var out CreateScanResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return CreateScanResponse{}, fmt.Errorf("portal: unmarshal create-scan response: %w", err)
	}
	return out, nil
}

// UploadJSON uploads body — the exact bytes an ungrouped
// jsonreport.New().Render() would produce — as the scan's JSON report. The
// caller is responsible for forcing GroupByNone before rendering; this
// method just transmits bytes.
func (c *Client) UploadJSON(ctx context.Context, scanID string, body []byte) error {
	path := fmt.Sprintf("/api/v1/scans/%s/upload/json", scanID)
	_, err := c.doRequest(ctx, http.MethodPost, path, body, "application/json")
	return err
}

// UploadHTML uploads htmlBody as a multipart form under field "file" to
// POST /api/v1/scans/{id}/upload/html.
func (c *Client) UploadHTML(ctx context.Context, scanID string, htmlBody []byte) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", "report.html")
	if err != nil {
		return fmt.Errorf("portal: build multipart body: %w", err)
	}
	if _, err := part.Write(htmlBody); err != nil {
		return fmt.Errorf("portal: write multipart body: %w", err)
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("portal: close multipart body: %w", err)
	}
	path := fmt.Sprintf("/api/v1/scans/%s/upload/html", scanID)
	_, err = c.doRequest(ctx, http.MethodPost, path, buf.Bytes(), mw.FormDataContentType())
	return err
}

type statusUpdateRequest struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// UpdateStatus reports a scan's terminal status to the portal — used when
// the pipeline itself fails in upload mode, so the portal doesn't show a
// permanently-pending scan with no explanation.
func (c *Client) UpdateStatus(ctx context.Context, scanID, status, errorMessage string) error {
	body, err := json.Marshal(statusUpdateRequest{Status: status, ErrorMessage: errorMessage})
	if err != nil {
		return fmt.Errorf("portal: marshal status-update request: %w", err)
	}
	path := fmt.Sprintf("/api/v1/scans/%s/status", scanID)
	_, err = c.doRequest(ctx, http.MethodPut, path, body, "application/json")
	return err
}

// doRequest mirrors internal/scanner/sca/osv.go's doRequest: build a fresh
// request each attempt, retry exactly once on a 5xx (2s backoff), no retry
// on a transport error or any 4xx. Success is any 2xx (the portal uses 201
// for CreateScan, unlike OSV's strict 200).
//
// ponytail: single hardcoded retry, no backoff/jitter tuning — these calls
// happen once per scan run, not in a hot loop. Add real backoff if a flaky
// portal deployment ever makes this matter.
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, error) {
	url := c.baseURL + path
	for attempt := 1; attempt <= 2; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("portal: build request: %w", err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("portal: request to %s failed: %w", url, err)
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("portal: read response from %s: %w", url, readErr)
		}

		if resp.StatusCode >= 500 && attempt == 1 {
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &HTTPError{StatusCode: resp.StatusCode, URL: url, Body: truncate(string(respBody), 500)}
		}
		return respBody, nil
	}
	return nil, fmt.Errorf("portal: request to %s failed after retry", url)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
