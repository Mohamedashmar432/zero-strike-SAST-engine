package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

// corsHeaderWildcardRe matches any "...origin...: *" / "...origin...=*" line,
// covering "Access-Control-Allow-Origin: *", "CORS_ORIGIN=*",
// "\"origin\": \"*\"", and "ALLOWED_ORIGINS=*" alike.
var corsHeaderWildcardRe = regexp.MustCompile(`(?i)origin[a-z_-]*["']?\s*[:=]\s*["']?\*`)

// corsWildcardSourceCallRe matches an explicit "Access-Control-Allow-Origin"
// header set to "*" in source code, covering both the key:value/key=value
// shape (Java's @CrossOrigin(origins = "*"), PHP's
// header('Access-Control-Allow-Origin: *')) and the comma-separated
// two-argument call shape (Go's w.Header().Set("Access-Control-Allow-Origin",
// "*"), C#'s Response.Headers.Add(...), Java's response.setHeader(...)).
// Deliberately anchored on the FULL header name, not the bare word "origin"
// that corsHeaderWildcardRe uses — general-purpose source files (unlike
// structured .env/.yaml/.json/.conf config files) can contain short
// identifiers named "origin" for unrelated reasons (e.g. Go's
// pointer-dereference syntax "origin = *ptr" would otherwise false-positive
// against corsHeaderWildcardRe).
var corsWildcardSourceCallRe = regexp.MustCompile(`(?i)access-control-allow-origin["']?\s*[:=,]\s*["']?\*`)

// corsWildcardCheck flags a wildcard CORS origin: as a raw
// "Access-Control-Allow-Origin: *" header/config line or a flattened YAML
// key containing "origin" (origin/allow_origin/allowedOrigins/...) whose
// value is "*" in config files, or the same header set to "*" via a
// header-setting call in Go/Java/C#/PHP source files.
var corsWildcardCheck = check{
	ruleID:  "ZS-CFG-003",
	accepts: isCorsConfigOrSourceFile,
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

// isCorsSourceFile matches source files in languages without a dedicated
// CORS AST rule (Go, Java, C#, PHP) that a header-setting call could appear
// in — scanned with the stricter full-header-name regex above, not the
// generic config-file regex.
func isCorsSourceFile(path string) bool {
	lower := strings.ToLower(path)
	for _, suffix := range []string{".go", ".java", ".cs", ".php"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func isCorsConfigOrSourceFile(path string) bool {
	return isCorsConfigFile(path) || isCorsSourceFile(path)
}

func detectCorsWildcard(path string, data []byte) []core.Finding {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return detectCorsWildcardYAML(path, data)
	}
	if isCorsSourceFile(path) {
		return detectCorsWildcardSourceCall(path, data)
	}
	return detectCorsWildcardText(path, data)
}

func detectCorsWildcardSourceCall(path string, data []byte) []core.Finding {
	lines := bytes.Split(data, []byte("\n"))
	var out []core.Finding
	for i, line := range lines {
		if corsWildcardSourceCallRe.Match(line) {
			out = append(out, buildCorsFinding(path, "Access-Control-Allow-Origin", "*", i+1))
		}
	}
	return out
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
