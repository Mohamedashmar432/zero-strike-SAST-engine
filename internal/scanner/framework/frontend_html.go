package framework

import (
	"os"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

// rawHTMLBindingCheck flags a template binding that renders a value as raw
// HTML ([innerHTML], [outerHTML], ng-bind-html, v-html) ONLY when the
// framework's sanitizer has been bypassed for that template:
//
//   - Angular [innerHTML]/[outerHTML]: Angular sanitizes these by default, so
//     the binding alone is safe. It is reported only when the sibling
//     component (foo.component.ts next to foo.component.html) or the template
//     itself calls DomSanitizer.bypassSecurityTrust*, which is how a value
//     reaches the binding unsanitized.
//   - AngularJS ng-bind-html: sanitized by $sanitize unless the page turns
//     Strict Contextual Escaping off ($sceProvider.enabled(false)) or marks
//     values trusted ($sce.trustAsHtml), which must appear in the same file.
//   - Vue v-html: Vue never sanitizes, so the bypass is inherent; reported
//     when the bound expression is not a constant string.
//
// Constant bindings ([innerHTML]="'KEY' | translate") are never reported.
// Confidence is always low: which bound value carries the bypassed data is
// not resolved, only that the template renders raw HTML while the sanitizer
// is off for it. It lives here rather than in the HTML rule pack because the
// Angular gate reads a second file, which the per-file SAST finding and AST
// caches (keyed on one file's content) cannot track.
var rawHTMLBindingCheck = check{
	ruleID:  "ZS-CFG-020",
	accepts: isHTMLFile,
	detect:  detectRawHTMLBinding,
}

func isHTMLFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm")
}

var (
	rawHTMLBindingRe = regexp.MustCompile(`(\[(?:innerHTML|outerHTML)\]|\b(?:data-)?ng-bind-html|\bv-html)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	bypassTrustRe    = regexp.MustCompile(`\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(`)
	sceDisabledRe    = regexp.MustCompile(`\$sceProvider\.enabled\(\s*false\s*\)|\btrustAsHtml\s*\(`)
)

func detectRawHTMLBinding(path string, data []byte) []core.Finding {
	src := string(data)
	if !strings.Contains(src, "innerHTML") && !strings.Contains(src, "outerHTML") &&
		!strings.Contains(src, "ng-bind-html") && !strings.Contains(src, "v-html") {
		return nil
	}
	matches := rawHTMLBindingRe.FindAllStringSubmatchIndex(src, -1)
	if len(matches) == 0 {
		return nil
	}

	angularGate, angularChecked := "", false
	var out []core.Finding
	for _, m := range matches {
		attr := src[m[2]:m[3]]
		expr := ""
		if m[4] >= 0 {
			expr = src[m[4]:m[5]]
		} else if m[6] >= 0 {
			expr = src[m[6]:m[7]]
		}
		expr = strings.TrimSpace(expr)
		if expr == "" || strings.HasPrefix(expr, "'") || strings.HasPrefix(expr, "\"") {
			continue // constant binding (often a translation key)
		}
		framework, gate := "", ""
		switch {
		case strings.HasPrefix(attr, "["):
			if !angularChecked {
				angularGate, angularChecked = angularBypassGate(path, src), true
			}
			framework, gate = "angular", angularGate
		case strings.HasSuffix(attr, "ng-bind-html"):
			if sceDisabledRe.MatchString(src) {
				framework, gate = "angularjs", "$sce disabled or trustAsHtml in this template"
			}
		case attr == "v-html":
			framework, gate = "vue", "Vue does not sanitize v-html"
		}
		if gate == "" {
			continue
		}
		line := strings.Count(src[:m[0]], "\n") + 1
		out = append(out, findings.BuildConfigFinding(
			"ZS-CFG-020",
			"Raw HTML Binding With Sanitization Bypassed",
			attr+"=\""+expr+"\" renders raw HTML while the sanitizer is bypassed ("+gate+"); an attacker-influenced value here is XSS",
			"xss",
			findings.ConfigInput{Framework: framework, ConfigFile: path, Key: attr + "=" + expr, Value: gate},
			core.Location{File: path, StartLine: line, EndLine: line},
			core.SeverityMedium,
			core.ConfidenceLow,
			[]string{"CWE-79"},
			[]string{"A05:2025"},
		))
	}
	return out
}

// angularBypassGate returns a description of where the sanitizer is
// bypassed for an Angular template, or "" when it is not: the template itself,
// or its sibling component class (x.component.html -> x.component.ts).
func angularBypassGate(path, src string) string {
	if bypassTrustRe.MatchString(src) {
		return "bypassSecurityTrust* in this template"
	}
	lower := strings.ToLower(path)
	for _, ext := range []string{".html", ".htm"} {
		if !strings.HasSuffix(lower, ext) {
			continue
		}
		sibling := path[:len(path)-len(ext)] + ".ts"
		if data, err := os.ReadFile(sibling); err == nil && bypassTrustRe.Match(data) {
			return "bypassSecurityTrust* in " + baseName(sibling)
		}
	}
	return ""
}
