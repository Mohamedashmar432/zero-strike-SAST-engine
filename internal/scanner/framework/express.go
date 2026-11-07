package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
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
	// Comments are blanked first: a commented-out require("helmet") or a
	// "Fix: use helmet" note is not a registration.
	if strings.Contains(strings.ToLower(string(stripJSComments(data))), "helmet") {
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
	// Hardening tier: missing security-header middleware is defence in depth
	// with no exploit path of its own, so it is left out of default output
	// and counted instead (see core.Tier).
	f.Tier = core.TierHardening
	return []core.Finding{f}
}

// stripJSComments blanks // and /* */ comments in JS/TS source, keeping
// newlines so line numbers survive. String and template literals are left
// alone so "http://x" is not read as a comment. A regex literal containing a
// quote can confuse it; the effect is a missed or extra comment span, which
// only matters to the substring tests that call it.
func stripJSComments(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	var quote byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote || (c == '\n' && quote != '`') {
				quote = 0
			}
			continue
		}
		switch {
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for ; i < len(src) && src[i] != '\n'; i++ {
				out[i] = ' '
			}
			i--
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			j := i + 2
			for j < len(src) && !(src[j-1] == '*' && src[j] == '/') {
				j++
			}
			for k := i; k <= j && k < len(src); k++ {
				if src[k] != '\n' {
					out[k] = ' '
				}
			}
			i = j
		}
	}
	return out
}
