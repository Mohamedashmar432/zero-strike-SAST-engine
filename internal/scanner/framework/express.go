package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
)

var (
	expressCallRe   = regexp.MustCompile(`\bexpress\s*\(`)
	expressListenRe = regexp.MustCompile(`\.listen\s*\(`)
)

// expressHelmetCheck flags an Express app entrypoint (express() + .listen()
// in the same file) with no helmet() registration anywhere in that file.
// Only fires in the entrypoint file — a router/middleware module that merely
// imports express is not flagged, accepting a false negative (helmet
// registered elsewhere) over noise on non-entrypoint files.
var expressHelmetCheck = check{
	ruleID:  "ZS-CFG-002",
	accepts: isJSFile,
	detect:  detectExpressMissingHelmet,
}

func isJSFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".ts")
}

func detectExpressMissingHelmet(path string, data []byte) []core.Finding {
	if !expressCallRe.Match(data) {
		return nil
	}
	if strings.Contains(strings.ToLower(string(data)), "helmet") {
		return nil
	}

	lines := bytes.Split(data, []byte("\n"))
	listenLine := 0
	for i, line := range lines {
		if expressListenRe.Match(line) {
			listenLine = i + 1
			break
		}
	}
	if listenLine == 0 {
		return nil
	}

	loc := core.Location{File: path, StartLine: listenLine, EndLine: listenLine}
	f := findings.BuildConfigFinding(
		"ZS-CFG-002",
		"Express App Missing Helmet",
		"Express app in "+path+" calls .listen() with no helmet() security headers middleware registered",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "express", ConfigFile: path, Key: "helmet"},
		loc,
		core.SeverityMedium,
		core.ConfidenceMedium,
		[]string{"CWE-693"},
		[]string{"A02:2025"},
	)
	return []core.Finding{f}
}
