package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

var phpIniCookieInsecureRe = regexp.MustCompile(`(?i)^\s*session\.cookie_(httponly|secure)\s*=\s*(0|off|false)\s*$`)

// phpIniCookieInsecureCheck flags session.cookie_httponly / session.cookie_secure
// disabled in php.ini. Laravel's own session config is covered by
// laravelSessionCookieCheck (ZS-CFG-009), but vanilla PHP apps (WordPress,
// legacy code) configure cookie flags at the php.ini level instead, which
// nothing else detects. PHP's positional setcookie($name,$value,...,$httponly)
// arguments can't be filter-matched (no positional-argument filter exists in
// the engine), so this text-based php.ini route is the correct fix rather
// than a YAML rule.
var phpIniCookieInsecureCheck = check{
	ruleID:  "ZS-CFG-011",
	accepts: isPhpIniFile,
	detect:  detectPhpIniCookieInsecure,
}

func isPhpIniFile(path string) bool {
	return strings.EqualFold(baseName(path), "php.ini")
}

func detectPhpIniCookieInsecure(path string, data []byte) []core.Finding {
	var out []core.Finding
	for i, line := range bytes.Split(data, []byte("\n")) {
		m := phpIniCookieInsecureRe.FindSubmatch(line)
		if m == nil {
			continue
		}
		key := "session.cookie_" + strings.ToLower(string(m[1]))
		out = append(out, buildPhpIniCookieFinding(path, key, i+1))
	}
	return out
}

func buildPhpIniCookieFinding(path, key string, line int) core.Finding {
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return findings.BuildConfigFinding(
		"ZS-CFG-011",
		"PHP Session Cookie Insecure",
		key+" disabled detected in "+path+" — session cookie security is weakened",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "php", ConfigFile: path, Key: key, Value: "0"},
		loc,
		core.SeverityMedium,
		core.ConfidenceMedium,
		[]string{"CWE-614"},
		[]string{"A02:2025"},
	)
}
