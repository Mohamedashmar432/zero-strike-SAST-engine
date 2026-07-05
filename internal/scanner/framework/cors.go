package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

// corsHeaderWildcardRe matches any "...origin...: *" / "...origin...=*" line,
// covering "Access-Control-Allow-Origin: *", "CORS_ORIGIN=*",
// "\"origin\": \"*\"", and "ALLOWED_ORIGINS=*" alike.
var corsHeaderWildcardRe = regexp.MustCompile(`(?i)origin[a-z_-]*["']?\s*[:=]\s*["']?\*`)

// corsWildcardCheck flags a wildcard CORS origin, either as a raw
// "Access-Control-Allow-Origin: *" header/config line, or as a flattened
// YAML key containing "origin" (origin/allow_origin/allowedOrigins/...)
// whose value is "*".
var corsWildcardCheck = check{
	ruleID:  "ZS-CFG-003",
	accepts: isCorsConfigFile,
	detect:  detectCorsWildcard,
}

func isCorsConfigFile(path string) bool {
	lower := strings.ToLower(path)
	if isEnvFile(path) {
		return true
	}
	for _, suffix := range []string{".yaml", ".yml", ".json", ".conf"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func detectCorsWildcard(path string, data []byte) []core.Finding {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return detectCorsWildcardYAML(path, data)
	}
	return detectCorsWildcardText(path, data)
}

func detectCorsWildcardYAML(path string, data []byte) []core.Finding {
	entries, err := ParseYAMLFlat(data)
	if err != nil {
		return nil
	}
	var out []core.Finding
	for _, e := range entries {
		if !strings.Contains(strings.ToLower(e.Path), "origin") {
			continue
		}
		if strings.TrimSpace(e.Value) != "*" {
			continue
		}
		out = append(out, buildCorsFinding(path, e.Path, "*", e.Line))
	}
	return out
}

func detectCorsWildcardText(path string, data []byte) []core.Finding {
	lines := bytes.Split(data, []byte("\n"))
	var out []core.Finding
	for i, line := range lines {
		if corsHeaderWildcardRe.Match(line) {
			out = append(out, buildCorsFinding(path, "Access-Control-Allow-Origin", "*", i+1))
		}
	}
	return out
}

func buildCorsFinding(path, key, value string, line int) core.Finding {
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return findings.BuildConfigFinding(
		"ZS-CFG-003",
		"Permissive CORS Configuration",
		"Wildcard CORS origin ("+key+" = "+value+") detected in "+path,
		"security-misconfiguration",
		findings.ConfigInput{Framework: "cors", ConfigFile: path, Key: key, Value: value},
		loc,
		core.SeverityMedium,
		core.ConfidenceMedium,
		[]string{"CWE-942"},
		[]string{"A02:2025"},
	)
}
