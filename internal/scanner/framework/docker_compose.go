package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

var dockerPrivilegedRe = regexp.MustCompile(`(?i)^\s*privileged\s*:\s*(true|1|yes|on)\s*$`)

// dockerComposePrivilegedCheck detects services configured with privileged: true in docker-compose files.
// Privileged containers disable isolation mechanisms and grant root-equivalent host access.
var dockerComposePrivilegedCheck = check{
	ruleID:  "ZS-CFG-013",
	accepts: isDockerComposeFile,
	detect:  detectDockerComposePrivileged,
}

func isDockerComposeFile(path string) bool {
	base := strings.ToLower(baseName(path))
	if base == "docker-compose.yml" || base == "docker-compose.yaml" ||
		base == "compose.yml" || base == "compose.yaml" {
		return true
	}
	if (strings.HasPrefix(base, "docker-compose.") || strings.HasPrefix(base, "compose.")) &&
		(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return true
	}
	return false
}

func detectDockerComposePrivileged(path string, data []byte) []core.Finding {
	var out []core.Finding
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		if dockerPrivilegedRe.Match(line) {
			out = append(out, buildDockerPrivilegedFinding(path, i+1))
		}
	}
	return out
}

func buildDockerPrivilegedFinding(path string, line int) core.Finding {
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return findings.BuildConfigFinding(
		"ZS-CFG-013",
		"Docker Compose Privileged Container",
		"privileged: true detected in "+path+" — containers should not run with full host privileges",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "docker-compose", ConfigFile: path, Key: "privileged", Value: "true"},
		loc,
		core.SeverityHigh,
		core.ConfidenceHigh,
		[]string{"CWE-250"},
		[]string{"A02:2025"},
	)
}
