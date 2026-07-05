package framework

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

// laravelDebugCheck flags APP_DEBUG=true in an .env file — Laravel's direct
// analogue of Django's DEBUG, not expressible as a PHP AST rule since .env
// isn't PHP source. Suppressed when the filename signals a non-prod file,
// or when the same .env's APP_ENV key signals a non-production environment.
var laravelDebugCheck = check{
	ruleID:  "ZS-CFG-004",
	accepts: isEnvFile,
	detect:  detectLaravelDebug,
}

func detectLaravelDebug(path string, data []byte) []core.Finding {
	if isLikelyNonProdEnvFile(path) {
		return nil
	}
	entries := ParseEnvFile(data)
	entry, ok := findEnvValue(entries, "APP_DEBUG")
	if !ok || !envValueIsTruthy(entry.Value) {
		return nil
	}
	if env, ok := findEnvValue(entries, "APP_ENV"); ok && envValueIsNonProd(env.Value) {
		return nil
	}
	loc := core.Location{File: path, StartLine: entry.Line, EndLine: entry.Line}
	f := findings.BuildConfigFinding(
		"ZS-CFG-004",
		"Laravel APP_DEBUG Enabled",
		"APP_DEBUG="+entry.Value+" detected in "+path+" — disable debug mode in production",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "laravel", ConfigFile: path, Key: "APP_DEBUG", Value: entry.Value},
		loc,
		core.SeverityHigh,
		core.ConfidenceMedium,
		[]string{"CWE-489"},
		[]string{"A02:2025"},
	)
	return []core.Finding{f}
}
