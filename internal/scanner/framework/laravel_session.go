package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

var (
	laravelSessionSecureFalseRe   = regexp.MustCompile(`(?i)'secure'\s*=>\s*(false\b|env\([^)]*,\s*false\s*\))`)
	laravelSessionHTTPOnlyFalseRe = regexp.MustCompile(`(?i)'http_only'\s*=>\s*false\b`)
	laravelExceptArrayRe          = regexp.MustCompile(`(?is)protected\s+\$except\s*=\s*\[(.*?)\]\s*;`)
)

// laravelSessionCookieCheck flags 'secure' => false / 'http_only' => false
// in config/session.php. This is pure text matching, not an AST rule,
// because Laravel's 'key' => value array entries are structurally
// invisible to the engine's kind: assignment matching (PHP's builder only
// maps assignment_expression, not array-literal pairs).
var laravelSessionCookieCheck = check{
	ruleID:  "ZS-CFG-009",
	accepts: isLaravelSessionConfigFile,
	detect:  detectLaravelSessionCookieInsecure,
}

// laravelCsrfExceptCheck flags a non-empty $except array in
// VerifyCsrfToken.php — every listed route pattern skips CSRF verification
// entirely.
var laravelCsrfExceptCheck = check{
	ruleID:  "ZS-CFG-010",
	accepts: isLaravelVerifyCsrfTokenFile,
	detect:  detectLaravelCsrfExcept,
}

func isLaravelSessionConfigFile(path string) bool {
	return strings.HasSuffix(normalizeSlashes(path), "config/session.php")
}

func isLaravelVerifyCsrfTokenFile(path string) bool {
	return strings.EqualFold(baseName(path), "VerifyCsrfToken.php")
}

func normalizeSlashes(path string) string {
	return strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
}

func detectLaravelSessionCookieInsecure(path string, data []byte) []core.Finding {
	var out []core.Finding
	for i, line := range bytes.Split(data, []byte("\n")) {
		if laravelSessionSecureFalseRe.Match(line) {
			out = append(out, buildLaravelSessionFinding(path, "secure", i+1))
		}
		if laravelSessionHTTPOnlyFalseRe.Match(line) {
			out = append(out, buildLaravelSessionFinding(path, "http_only", i+1))
		}
	}
	return out
}

func buildLaravelSessionFinding(path, key string, line int) core.Finding {
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return findings.BuildConfigFinding(
		"ZS-CFG-009",
		"Laravel Session Cookie Insecure",
		"'"+key+"' => false detected in "+path+" — session cookie security is weakened",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "laravel", ConfigFile: path, Key: key, Value: "false"},
		loc,
		core.SeverityMedium,
		core.ConfidenceMedium,
		[]string{"CWE-614"},
		[]string{"A02:2025"},
	)
}

// detectLaravelCsrfExcept flags a $except array containing at least one
// quoted route pattern. A bare `protected $except = [];` (or one with only
// whitespace/comments between the brackets) is not flagged.
func detectLaravelCsrfExcept(path string, data []byte) []core.Finding {
	loc := laravelExceptArrayRe.FindSubmatchIndex(data)
	if loc == nil {
		return nil
	}
	body := string(data[loc[2]:loc[3]])
	if !strings.ContainsAny(body, "'\"") {
		return nil
	}
	line := 1 + bytes.Count(data[:loc[0]], []byte("\n"))
	fLoc := core.Location{File: path, StartLine: line, EndLine: line}
	return []core.Finding{findings.BuildConfigFinding(
		"ZS-CFG-010",
		"Laravel CSRF Protection Bypassed",
		"Non-empty $except array detected in "+path+" — listed routes skip CSRF verification entirely",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "laravel", ConfigFile: path, Key: "$except"},
		fLoc,
		core.SeverityHigh,
		core.ConfidenceMedium,
		[]string{"CWE-352"},
		[]string{"A01:2025"},
	)}
}
