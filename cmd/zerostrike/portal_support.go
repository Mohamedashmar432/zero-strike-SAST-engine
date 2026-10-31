// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
	jsonreport "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report/json"
	scascan "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/scanner/sca"
)

// uploadFlagsError enforces that --server/--token are either both set
// (upload mode) or both unset (local-only) — a partial set almost
// certainly means a forgotten flag, not an intentional local-only scan.
// --project-id is no longer part of this check: the token alone resolves
// the project server-side (kept as a deprecated, accepted-but-ignored flag
// for backward compatibility with older committed CI pipeline YAML).
func uploadFlagsError(server, token string) error {
	set := 0
	for _, v := range []string{server, token} {
		if v != "" {
			set++
		}
	}
	if set != 0 && set != 2 {
		return fmt.Errorf("--server and --token must be set together (upload mode) or both omitted (local-only scan)")
	}
	return nil
}

// uploadEnabled reports whether upload mode is active.
func uploadEnabled(server, token string) bool {
	return server != "" && token != ""
}

// describePortalError formats a distinguishing, user-facing message for a
// portal API failure — an invalid/expired/revoked token reads very
// differently from "the server is down," even though both currently drive
// the same exit code.
func describePortalError(action string, err error) string {
	var httpErr *portal.HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode == http.StatusUnauthorized {
			return fmt.Sprintf("%s: invalid, expired, or revoked portal token (HTTP 401)", action)
		}
		return fmt.Sprintf("%s: portal returned HTTP %d: %s", action, httpErr.StatusCode, httpErr.Body)
	}
	return fmt.Sprintf("%s: %v", action, err)
}

// buildUploadJSON renders rep as JSON for portal upload, always ungrouped
// regardless of rep.GroupBy — the portal expects a flat Findings array;
// --group-by is a local reporting convenience only and must never change
// what the portal receives.
func buildUploadJSON(rep *report.Report) ([]byte, error) {
	uploadRep := *rep
	uploadRep.GroupBy = report.GroupByNone
	var buf bytes.Buffer
	if err := jsonreport.New().Render(&uploadRep, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decideExitCode is scan's post-run exit-code precedence rule: an upload
// failure (2) takes precedence over findings-found (1). The local report
// file already shows findings either way, but an upload failure is the one
// outcome the user has no other way to notice, so it must not be masked.
func decideExitCode(findingsCount int, uploadFailed bool) int {
	if uploadFailed {
		return 2
	}
	if findingsCount > 0 {
		return 1
	}
	return 0
}

// ciBranchEnvVars are the CI-provided branch names, tried in order when git
// reports a detached HEAD (the normal state of a CI checkout).
var ciBranchEnvVars = []string{
	"GITHUB_HEAD_REF",
	"GITHUB_REF_NAME",
	"SYSTEM_PULLREQUEST_SOURCEBRANCH",
	"BUILD_SOURCEBRANCHNAME",
	"CI_COMMIT_REF_NAME",
}

// gitInfo returns the current HEAD commit SHA, branch name and sanitized
// origin repo URL for repoRoot. Best-effort only: any failure (git not on
// PATH, repoRoot not a git checkout, detached HEAD, etc.) yields empty
// strings, never an error — a scan must never fail just because it isn't run
// inside a git repository. In CI, HEAD is detached and the remote may be
// absent, so branch and repo URL fall back to the CI system's env vars.
func gitInfo(ctx context.Context, repoRoot string) (commit, branch, repoURL string) {
	commit = runGit(ctx, repoRoot, "rev-parse", "HEAD")

	branch = runGit(ctx, repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		branch = "" // detached HEAD has no meaningful branch name
	}
	for _, name := range ciBranchEnvVars {
		if branch != "" {
			break
		}
		branch = strings.TrimSpace(os.Getenv(name))
	}
	branch = strings.TrimPrefix(branch, "refs/heads/")

	raw := runGit(ctx, repoRoot, "remote", "get-url", "origin")
	if raw == "" {
		if server, repo := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"); server != "" && repo != "" {
			raw = strings.TrimRight(server, "/") + "/" + repo
		}
	}
	if raw == "" {
		raw = os.Getenv("BUILD_REPOSITORY_URI")
	}
	if raw == "" {
		raw = os.Getenv("CI_PROJECT_URL")
	}
	return commit, branch, sanitizeRepoURL(raw)
}

// sanitizeRepoURL reduces a git remote to a credential-free http(s) URL, or
// "" when that isn't possible. Userinfo is dropped entirely (a token may sit
// in the username slot), as are the query and fragment. scp-style
// git@host:org/repo remotes are rewritten to https://host/org/repo.
func sanitizeRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		// scp-like syntax: [user@]host:path
		at := strings.LastIndex(raw, "@")
		hostPath := raw[at+1:]
		host, path, ok := strings.Cut(hostPath, ":")
		if !ok || host == "" || path == "" || strings.Contains(host, "/") {
			return ""
		}
		raw = "https://" + host + "/" + strings.TrimLeft(path, "/")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	if !repoPathPlausible(strings.ToLower(u.Hostname()), u.Path) {
		return ""
	}
	return u.String()
}

var tokenPathPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "gldt-", "xox"}

// segmentLooksLikeToken reports whether one URL path segment looks like a
// pasted credential: a known token prefix, a literal x-access-token/oauth2
// user, or 32+ chars of [A-Za-z0-9_-] mixing upper, lower and digits.
func segmentLooksLikeToken(seg string) bool {
	low := strings.ToLower(seg)
	if low == "x-access-token" || low == "oauth2" {
		return true
	}
	for _, p := range tokenPathPrefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	if len(seg) < 32 {
		return false
	}
	var upper, lower, digit bool
	for _, r := range seg {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return upper && lower && digit
}

// repoPathPlausible rejects a repo path carrying a credential and, for hosts
// whose layout is fixed, a path of the wrong shape. gitlab.com and
// self-hosted hosts (subgroups) get no length cap. Mirrors the portal's
// sanitize_repo_url; keep the shared test vectors in sync.
func repoPathPlausible(host, path string) bool {
	var segs []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if n := len(segs); n > 0 {
		segs[n-1] = strings.TrimSuffix(segs[n-1], ".git")
	}
	for _, s := range segs {
		if segmentLooksLikeToken(s) {
			return false
		}
	}
	switch {
	case host == "github.com" || host == "bitbucket.org":
		return len(segs) == 2
	case host == "dev.azure.com":
		return len(segs) == 4 && segs[2] == "_git"
	case strings.HasSuffix(host, ".visualstudio.com"):
		return len(segs) >= 2 && segs[len(segs)-2] == "_git"
	}
	return true
}

func runGit(ctx context.Context, dir string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// exemptionsFileEnv names a JSON file of exemptions (the portal's accepted_exemptions array) for a
// scan run without --server/--token -- the Azure DevOps Classic scripts register the scan
// themselves and hand the list over this way. An older scanner simply ignores the variable.
const exemptionsFileEnv = "ZEROSTRIKE_ACCEPTED_EXEMPTIONS_FILE"

// loadExemptionsFile reads exemptions from path. A missing or unreadable file is an error the caller
// reports: silently ignoring it would make an exempted finding block the pipeline with no clue why.
func loadExemptionsFile(path string) ([]portal.Exemption, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []portal.Exemption
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

// repoRelative is the form the portal stores a finding's path in, so an exemption can be compared:
// forward slashes, the scan root stripped (the scanner echoes an absolute root in every path when
// it was started with one, e.g. Azure DevOps' $BUILD_SOURCESDIRECTORY), and no leading "./".
func repoRelative(file, rootPath, absRoot string) string {
	f := strings.ReplaceAll(file, "\\", "/")
	for _, root := range []string{absRoot, rootPath} {
		r := strings.TrimRight(strings.ReplaceAll(root, "\\", "/"), "/")
		if r == "" || r == "." {
			continue
		}
		if strings.HasPrefix(f, r+"/") {
			f = f[len(r)+1:]
			break
		}
	}
	for strings.HasPrefix(f, "./") {
		f = f[2:]
	}
	return f
}

// applyExemptions splits findings into those that count and those an admin-accepted exemption
// matches -- by fingerprint AND repo-relative file, never by fingerprint alone.
func applyExemptions(findings []core.Finding, exemptions []portal.Exemption, rootPath, absRoot string) ([]core.Finding, []report.ExemptedFinding) {
	if len(exemptions) == 0 {
		return findings, nil
	}
	kinds := make(map[[2]string]string, len(exemptions))
	for _, e := range exemptions {
		kinds[[2]string{e.Fingerprint, repoRelative(e.File, "", "")}] = e.Kind
	}
	active := make([]core.Finding, 0, len(findings))
	var exempted []report.ExemptedFinding
	for _, f := range findings {
		rel := repoRelative(f.Location.File, rootPath, absRoot)
		if kind, ok := kinds[[2]string{f.Fingerprint, rel}]; ok && f.Fingerprint != "" {
			exempted = append(exempted, report.ExemptedFinding{Fingerprint: f.Fingerprint, File: rel, Kind: kind, Finding: f})
			continue
		}
		active = append(active, f)
	}
	return active, exempted
}

// maxDependencyRefs bounds Report.Dependencies so a monorepo with an enormous lockfile set cannot
// produce an unbounded report. Beyond it the sorted list is truncated, with a warning.
const maxDependencyRefs = 50000

// buildDependencyRefs turns the SCA inventory into the report's sorted, repo-relative
// Dependencies array. nil in (SCA did not run) gives nil out, so the key is omitted; an empty
// non-nil inventory gives an empty non-nil slice, which serialises as [].
//
// Direct is passed through untouched. The yarn and pnpm parsers set Direct=true for every
// entry, so consumers must not trust it for those lockfiles.
func buildDependencyRefs(deps []scascan.Dependency, rootPath, absRoot string) []report.DependencyRef {
	if deps == nil {
		return nil
	}
	out := make([]report.DependencyRef, 0, len(deps))
	for _, d := range deps {
		out = append(out, report.DependencyRef{
			Ecosystem: d.Ecosystem,
			Package:   d.Package,
			Version:   d.Version,
			Manifest:  repoRelative(d.Manifest, rootPath, absRoot),
			Direct:    d.Direct,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Manifest < b.Manifest
	})
	if len(out) > maxDependencyRefs {
		fmt.Fprintf(os.Stderr, "WARNING: dependency inventory truncated to %d of %d entries; the portal will not match new advisories against the rest\n", maxDependencyRefs, len(out))
		out = out[:maxDependencyRefs]
	}
	return out
}
