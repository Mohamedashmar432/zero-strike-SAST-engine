package taint

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// SQL-class neutralization (Result.SQLSafe). Unlike the global Sanitizers, these
// clear taint for SQL sinks only: an escape function does not make a value safe
// to echo, and a numeric cast does not make it safe in a shell command.
const (
	// SQLSafeQuoted marks a value that is safe only between SQL quotes: a string
	// escape (mysqli_real_escape_string) does nothing for `WHERE id = $id`.
	SQLSafeQuoted int8 = 1
	// SQLSafeAny marks a value safe in any SQL position: a numeric cast, a hash
	// or hex digest, or a whole query whose every tainted part is neutralized.
	SQLSafeAny int8 = 2
)

var phpVarToken = regexp.MustCompile(`\$\w+`)

// sqlClass classifies the value an assignment produces. It returns 0 unless
// every tainted ingredient of the RHS is neutralized for SQL: the RHS runs a SQL
// sanitizer over what it takes, and any tainted variable left outside those
// calls is itself SQL-safe (a quote-only one must sit between quotes at every
// use in the RHS).
func sqlClass(n *ir.IRNode, pats languagePatterns, tainted map[string]bool, sqlSafe map[string]int8) int8 {
	if len(pats.SQLQuote) == 0 && len(pats.SQLAny) == 0 && len(pats.SQLCast) == 0 {
		return 0
	}
	rhs, _ := n.Attrs["rhs"].(string)
	rest, quoted := stripCalls(rhs, pats.SQLQuote)
	rest, anyCall := stripCalls(rest, pats.SQLAny)
	cast := false
	for _, re := range pats.SQLCast {
		if re.MatchString(rest) {
			cast = true
			rest = re.ReplaceAllString(rest, "")
		}
	}
	if matchesAny(pats.Sources, rest) {
		return 0
	}
	seen := quoted || anyCall || cast
	done := map[string]bool{}
	for _, tok := range phpVarToken.FindAllString(rest, -1) {
		if done[tok] || !tainted[tok] {
			continue
		}
		done[tok] = true
		switch sqlSafe[tok] {
		case SQLSafeAny:
		case SQLSafeQuoted:
			if !alwaysQuoted(rest, tok) {
				return 0
			}
		default:
			return 0
		}
		seen = true
	}
	switch {
	case !seen:
		return 0
	case quoted:
		return SQLSafeQuoted
	}
	return SQLSafeAny
}

// alwaysQuoted reports whether every occurrence of variable tok in expr sits
// between quote characters: "'$x'", "'{$x}'" or "'" . $x . "'".
func alwaysQuoted(expr, tok string) bool {
	q := regexp.QuoteMeta(tok)
	total := len(regexp.MustCompile(q + `\b`).FindAllStringIndex(expr, -1))
	inQuotes := len(regexp.MustCompile(`'\s*\{?`+q+`\b\}?\s*'`).FindAllStringIndex(expr, -1)) +
		len(regexp.MustCompile(`'["']?\s*\.\s*`+q+`\b\s*\.\s*["']?\\?'`).FindAllStringIndex(expr, -1))
	return total > 0 && total == inQuotes
}

// stripCalls removes every call matching one of res (whose pattern ends at the
// opening parenthesis) from s, through its balanced closing parenthesis.
func stripCalls(s string, res []*regexp.Regexp) (string, bool) {
	found := false
	for _, re := range res {
		for {
			loc := re.FindStringIndex(s)
			if loc == nil {
				break
			}
			end := closingParen(s, loc[1]-1)
			if end < 0 {
				end = len(s) - 1
			}
			s = s[:loc[0]] + " " + s[end+1:]
			found = true
		}
	}
	return strings.TrimSpace(s), found
}

// closingParen returns the index of the parenthesis closing the one at open,
// skipping quoted strings, or -1.
func closingParen(s string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
