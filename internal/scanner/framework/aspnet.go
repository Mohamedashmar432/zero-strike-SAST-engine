package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

var (
	customErrorsOffRe        = regexp.MustCompile(`(?i)<customErrors[^>]*\bmode\s*=\s*"off"`)
	directoryBrowseEnabledRe = regexp.MustCompile(`(?i)<directoryBrowse[^>]*\benabled\s*=\s*"true"`)
)

// aspnetVerboseErrorsCheck flags <customErrors mode="Off"> in web.config —
// unhandled exceptions render a full stack trace (and any local variable
// values ASP.NET chooses to include) directly to the client.
var aspnetVerboseErrorsCheck = check{
	ruleID:  "ZS-CFG-007",
	accepts: isWebConfigFile,
	detect:  detectAspNetVerboseErrors,
}

// aspnetDirectoryBrowseCheck flags <directoryBrowse enabled="true"> in
// web.config — directory contents become listable by any visitor.
var aspnetDirectoryBrowseCheck = check{
	ruleID:  "ZS-CFG-008",
	accepts: isWebConfigFile,
	detect:  detectAspNetDirectoryBrowse,
}

func isWebConfigFile(path string) bool {
	return strings.EqualFold(baseName(path), "web.config")
}

func detectAspNetVerboseErrors(path string, data []byte) []core.Finding {
	return matchLines(data, customErrorsOffRe, func(line int) core.Finding {
		loc := core.Location{File: path, StartLine: line, EndLine: line}
		return findings.BuildConfigFinding(
			"ZS-CFG-007",
			"ASP.NET Custom Errors Disabled",
			`<customErrors mode="Off"> detected in `+path+" — unhandled exceptions will render a full stack trace to the client",
			"security-misconfiguration",
			findings.ConfigInput{Framework: "aspnet", ConfigFile: path, Key: "customErrors", Value: "Off"},
			loc,
			core.SeverityMedium,
			core.ConfidenceMedium,
			[]string{"CWE-209"},
			[]string{"A02:2025"},
		)
	})
}

func detectAspNetDirectoryBrowse(path string, data []byte) []core.Finding {
	return matchLines(data, directoryBrowseEnabledRe, func(line int) core.Finding {
		loc := core.Location{File: path, StartLine: line, EndLine: line}
		return findings.BuildConfigFinding(
			"ZS-CFG-008",
			"ASP.NET Directory Browsing Enabled",
			`<directoryBrowse enabled="true"> detected in `+path+" — directory contents are listable by any visitor",
			"security-misconfiguration",
			findings.ConfigInput{Framework: "aspnet", ConfigFile: path, Key: "directoryBrowse", Value: "true"},
			loc,
			core.SeverityMedium,
			core.ConfidenceMedium,
			[]string{"CWE-548"},
			[]string{"A05:2025"},
		)
	})
}

// matchLines runs re against each line of data and returns one finding per
// matching line, built by build.
func matchLines(data []byte, re *regexp.Regexp, build func(line int) core.Finding) []core.Finding {
	var out []core.Finding
	for i, line := range bytes.Split(data, []byte("\n")) {
		if re.Match(line) {
			out = append(out, build(i+1))
		}
	}
	return out
}
