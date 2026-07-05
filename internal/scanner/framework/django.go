package framework

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

// djangoDebugCheck flags DEBUG=True in an .env-style file. Django settings
// modules driven by django-environ/python-decouple read DEBUG from the
// environment, which the Python AST rule ZS-PY-017 cannot see (it only
// matches a literal `DEBUG = True` assignment in .py source).
var djangoDebugCheck = check{
	ruleID:  "ZS-CFG-001",
	accepts: isEnvFile,
	detect:  detectDjangoDebug,
}

func detectDjangoDebug(path string, data []byte) []core.Finding {
	if isLikelyNonProdEnvFile(path) {
		return nil
	}
	entries := ParseEnvFile(data)
	entry, ok := findEnvValue(entries, "DEBUG")
	if !ok || !envValueIsTruthy(entry.Value) {
		return nil
	}
	loc := core.Location{File: path, StartLine: entry.Line, EndLine: entry.Line}
	f := findings.BuildConfigFinding(
		"ZS-CFG-001",
		"Django DEBUG Enabled",
		"DEBUG="+entry.Value+" detected in "+path+" — disable debug mode in production",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "django", ConfigFile: path, Key: "DEBUG", Value: entry.Value},
		loc,
		core.SeverityHigh,
		core.ConfidenceMedium,
		[]string{"CWE-489"},
		[]string{"A02:2025"},
	)
	return []core.Finding{f}
}
