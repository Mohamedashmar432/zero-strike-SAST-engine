// Package suppress honours inline suppression comments written by the author
// of the scanned code.
//
// Without this a codebase cannot converge on a clean scan: a reviewer decides a
// finding is acceptable, writes down why, and the next run reports it again. The
// repository that motivated this carried one `// nosemgrep` and 26 `# noqa`
// annotations, several with multi-line justifications, and the engine honoured
// none of them.
package suppress

import (
	"strings"
)

// markers are the suppression keywords recognised on a comment line, covering
// the annotations already present in real codebases rather than inventing a
// new one nobody has written yet.
var markers = []string{"zerostrike-ignore", "zs-ignore", "nosemgrep", "nosec", "noqa"}

// commentStarters introduce a comment in the languages the engine parses.
// A marker is only honoured after one of these, so a string literal that
// happens to contain "noqa" does not silently suppress a real finding.
var commentStarters = []string{"#", "//", "/*", "--", "<!--"}

// Suppressed reports whether a finding for ruleID carries an inline
// suppression. startLine and endLine are the finding's 1-based reported span;
// pass the same value for both when the finding is a single line.
//
// The search covers the line above startLine and every line of the span. The
// span matters more than it looks: a rule matching `kind: try` reports at the
// `try:` line, but the thing an author annotates is the `except` clause
// several lines down. Checking only the first line meant a suppression written
// exactly where a reader would put it did nothing.
//
// Rule-ID semantics are deliberately strict: a marker followed by identifiers
// suppresses only when one of them is this engine's rule ID. A foreign tool's
// code does not suppress a ZeroStrike finding: `# noqa: BLE001` is a ruff
// annotation about an exception-handling lint, and treating it as blanket
// permission would have hidden all three genuine empty-handler findings in the
// report that motivated this package. That strictness is also what keeps the
// span search safe, since an unrelated `# noqa: E501` inside a long try block
// suppresses nothing. A bare marker with no identifiers is treated as blanket
// suppression, since that is what the author meant.
func Suppressed(source []byte, startLine, endLine int, ruleID string) bool {
	if startLine <= 0 {
		return false
	}
	if endLine < startLine {
		endLine = startLine
	}
	lines := splitLines(string(source))

	for n := startLine - 1; n <= endLine; n++ {
		if n <= 0 || n > len(lines) {
			continue
		}
		if lineSuppresses(lines[n-1], ruleID) {
			return true
		}
	}
	return false
}

// lineSuppresses reports whether a single source line carries a suppression
// marker that applies to ruleID.
func lineSuppresses(text, ruleID string) bool {
	comment, ok := commentPart(text)
	if !ok {
		return false
	}
	lower := strings.ToLower(comment)
	for _, m := range markers {
		i := strings.Index(lower, m)
		if i < 0 {
			continue
		}
		ids := parseIDs(comment[i+len(m):])
		if len(ids) == 0 {
			return true // bare marker: blanket suppression
		}
		for _, id := range ids {
			if strings.EqualFold(id, ruleID) {
				return true
			}
		}
	}
	return false
}

// commentPart returns the portion of text starting at its first comment
// starter, and whether one was found.
func commentPart(text string) (string, bool) {
	best := -1
	for _, c := range commentStarters {
		if i := strings.Index(text, c); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	return text[best:], true
}

// parseIDs extracts the rule identifiers following a marker.
//
// Accepts an optional colon, then identifiers separated by commas or spaces,
// stopping at the first token that begins free-form prose. That stop matters:
// `# noqa: BLE001 -- a missing or corrupt asset must not fail an approval`
// must yield exactly ["BLE001"], not every word of the justification.
func parseIDs(rest string) []string {
	rest = strings.TrimSpace(rest)
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimPrefix(rest, "=")

	var ids []string
	for _, tok := range strings.FieldsFunc(rest, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		// Prose separators end the identifier list.
		if tok == "--" || tok == "-" || strings.HasPrefix(tok, "--") {
			break
		}
		// An identifier is a bare token; anything containing prose punctuation
		// is the start of a justification.
		if strings.ContainsAny(tok, "\"'()") {
			break
		}
		ids = append(ids, strings.Trim(tok, ".,;"))
	}
	return ids
}

// splitLines splits source into lines, tolerating CRLF and a missing trailing
// newline.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}
