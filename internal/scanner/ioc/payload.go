package ioc

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-002: an executor applied to a decoder, where the decoded blob is a
// long literal (200+ characters in total) or the decoders are chained.
//
// The executor must be a bare call: `re.exec(s)`, `cursor.execute(...)`,
// `$this->assert(...)` and `child_process.exec(cmd)` are member calls on
// something else and never match. Analysis is per call, on the balanced
// argument text, so a payload split over several lines or concatenated
// literals still counts.

const minPayloadLiteral = 200

var payloadExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true,
	".php": true, ".phtml": true, ".php5": true, ".inc": true,
	".py": true,
}

// callArgs returns the text between the parenthesis at text[open] and its
// match, skipping parentheses inside string literals, plus the end offset. ok
// is false when the call is not closed within the scan limit.
func callArgs(text string, open int) (args string, end int, ok bool) {
	const limit = 1 << 18
	depth := 0
	for i := open; i < len(text) && i-open < limit; i++ {
		switch c := text[i]; c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return text[open+1 : i], i + 1, true
			}
		case '\'', '"', '`':
			i = skipString(text, i)
		}
	}
	return "", 0, false
}

// skipString returns the index of the last character of the string literal
// starting at text[i] (the closing quote, or the end of text). Python triple
// quotes are honoured.
func skipString(text string, i int) int {
	q := text[i]
	if i+2 < len(text) && text[i+1] == q && text[i+2] == q {
		if e := strings.Index(text[i+3:], strings.Repeat(string(q), 3)); e >= 0 {
			return i + 3 + e + 2
		}
		return len(text) - 1
	}
	for j := i + 1; j < len(text); j++ {
		switch text[j] {
		case '\\':
			j++
		case q:
			return j
		case '\n':
			if q != '`' {
				// An unterminated literal ends at the line break; this also
				// keeps an apostrophe in a comment from swallowing the file.
				return j
			}
		}
	}
	return len(text) - 1
}

// literalLength sums the length of every string literal in s.
func literalLength(s string) int {
	total := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '`':
			e := skipString(s, i)
			if e > i {
				total += e - i - 1
			}
			i = e
		}
	}
	return total
}

var assignDecode = regexp.MustCompile(`(\$?[A-Za-z_]\w*)\s*=\s*$`)

func (s *Scanner) encodedPayload(f *file) []core.Finding {
	if f.nonShipped || !payloadExts[f.ext] {
		return nil
	}
	m := s.m
	// Variables assigned a decoded long literal or a decode chain, for the
	// two-step shape `$p = base64_decode("...")` then `eval($p)`.
	suspect := map[string]bool{}
	for _, loc := range m.decoder.FindAllStringIndex(f.text, -1) {
		open := strings.IndexByte(f.text[loc[0]:], '(')
		if open < 0 {
			continue
		}
		args, _, ok := callArgs(f.text, loc[0]+open)
		if !ok {
			continue
		}
		if literalLength(args) < minPayloadLiteral && !m.decoder.MatchString(args) {
			continue
		}
		// Only a decoder that is the whole right-hand side counts.
		before := f.text[max(0, loc[0]-80):loc[0]]
		if i := strings.LastIndexByte(before, 10); i >= 0 {
			before = before[i+1:]
		}
		if a := assignDecode.FindStringSubmatch(before); a != nil {
			suspect[a[1]] = true
		}
	}

	var out []core.Finding
	seen := map[int]bool{}
	for _, loc := range m.executor.FindAllStringSubmatchIndex(f.text, -1) {
		start := loc[0]
		if start > 0 && isMemberPrefix(f.text, start) {
			continue
		}
		if inCommentLine(f, start) {
			continue
		}
		open := loc[1] - 1 // the "(" the pattern ends on, possibly after spaces
		for open > start && f.text[open] != '(' {
			open--
		}
		args, _, ok := callArgs(f.text, open)
		if !ok {
			continue
		}
		name := f.text[loc[2]:loc[3]]
		reason := ""
		decodes := len(m.decoder.FindAllStringIndex(args, -1))
		switch {
		case decodes >= 2:
			reason = "a chain of " + strconv.Itoa(decodes) + " decoders"
		case decodes == 1 && literalLength(args) >= minPayloadLiteral:
			reason = "a decoded literal of " + strconv.Itoa(literalLength(args)) + " characters"
		default:
			if v := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(args), "@")); suspect[v] {
				reason = "variable " + v + ", which holds a decoded long literal"
			}
		}
		if reason == "" || seen[start] {
			continue
		}
		seen[start] = true
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-002", offset: start,
			snippet:   f.lines[f.lineAt(start)-1],
			message:   name + "() runs " + reason,
			indicator: name,
			lang:      langForExt(f.ext),
		}))
	}
	return out
}

// isMemberPrefix reports whether the identifier at text[start] is a member of
// something (`x.exec(`, `$this->assert(`, `Foo::assert(`) or part of a longer
// name (`my_eval(`, `$eval(`), except the global-object forms.
func isMemberPrefix(text string, start int) bool {
	c := text[start-1]
	switch {
	case c == '.':
		head := strings.TrimRight(text[max(0, start-12):start-1], " ")
		return !(strings.HasSuffix(head, "window") || strings.HasSuffix(head, "globalThis") ||
			strings.HasSuffix(head, "global") || strings.HasSuffix(head, "self"))
	case c == '>' || c == ':' || c == '$' || c == '_':
		return true
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return false
}

// inCommentLine reports whether the offset sits on a line that is only a
// comment.
func inCommentLine(f *file, off int) bool {
	t := strings.TrimSpace(f.lines[f.lineAt(off)-1])
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*")
}
