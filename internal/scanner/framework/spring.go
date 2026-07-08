package framework

import (
	"strings"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

// springActuatorExposedCheck flags management.endpoints.web.exposure.include=*
// in a Spring Boot application.properties/.yml — exposing every actuator
// endpoint (including /env, /heapdump, /shutdown) rather than an explicit
// allowlist.
var springActuatorExposedCheck = check{
	ruleID:  "ZS-CFG-005",
	accepts: isSpringConfigFile,
	detect:  detectSpringActuatorExposed,
}

// springCookieInsecureCheck flags server.servlet.session.cookie.secure=false
// in the same file types.
var springCookieInsecureCheck = check{
	ruleID:  "ZS-CFG-006",
	accepts: isSpringConfigFile,
	detect:  detectSpringCookieInsecure,
}

func isSpringConfigFile(path string) bool {
	base := strings.ToLower(baseName(path))
	if !strings.HasPrefix(base, "application") {
		return false
	}
	for _, suffix := range []string{".properties", ".yml", ".yaml"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func detectSpringActuatorExposed(path string, data []byte) []core.Finding {
	value, line, ok := findSpringKey(path, data, "management.endpoints.web.exposure.include")
	if !ok || strings.TrimSpace(value) != "*" {
		return nil
	}
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return []core.Finding{findings.BuildConfigFinding(
		"ZS-CFG-005",
		"Spring Boot Actuator Fully Exposed",
		"management.endpoints.web.exposure.include=* detected in "+path+" — every actuator endpoint (including /env, /heapdump, /shutdown) is exposed",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "spring", ConfigFile: path, Key: "management.endpoints.web.exposure.include", Value: value},
		loc,
		core.SeverityHigh,
		core.ConfidenceMedium,
		[]string{"CWE-16"},
		[]string{"A05:2025"},
	)}
}

func detectSpringCookieInsecure(path string, data []byte) []core.Finding {
	value, line, ok := findSpringKey(path, data, "server.servlet.session.cookie.secure")
	if !ok || strings.ToLower(strings.TrimSpace(value)) != "false" {
		return nil
	}
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return []core.Finding{findings.BuildConfigFinding(
		"ZS-CFG-006",
		"Spring Boot Session Cookie Not Secure",
		"server.servlet.session.cookie.secure=false detected in "+path+" — session cookie will be sent over plain HTTP",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "spring", ConfigFile: path, Key: "server.servlet.session.cookie.secure", Value: value},
		loc,
		core.SeverityMedium,
		core.ConfidenceMedium,
		[]string{"CWE-614"},
		[]string{"A02:2025"},
	)}
}

// findSpringKey looks up a dotted key in either a .properties file
// (KEY=VALUE lines, via ParseProperties) or a .yml/.yaml file (flattened
// dotted paths, via ParseYAMLFlat).
func findSpringKey(path string, data []byte, key string) (value string, line int, ok bool) {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
		entries, err := ParseYAMLFlat(data)
		if err != nil {
			return "", 0, false
		}
		for _, e := range entries {
			if strings.EqualFold(e.Path, key) {
				return e.Value, e.Line, true
			}
		}
		return "", 0, false
	}
	entries := ParseProperties(data)
	entry, found := findEnvValue(entries, key)
	if !found {
		return "", 0, false
	}
	return entry.Value, entry.Line, true
}
