package taint

import (
	"regexp"

	"github.com/zerostrike/scanner/internal/core"
)

// languagePatterns holds the per-language taint configuration: expression
// text that introduces taint (Sources) and calls that neutralize it
// (Sanitizers). These live in Go, not in rule YAML, because dozens of rules
// share the same lists via the file-level tainted-variable set — see
// internal/engine's TaintedArgument/TaintedRHS filters.
type languagePatterns struct {
	Sources    []*regexp.Regexp
	Sanitizers []*regexp.Regexp
}

var pythonPatterns = languagePatterns{
	Sources: []*regexp.Regexp{
		regexp.MustCompile(`request\.(args|form|GET|POST|values)`),
		regexp.MustCompile(`(^|\W)input\(`),
		regexp.MustCompile(`sys\.argv`),
		regexp.MustCompile(`os\.environ\.get`),
	},
	Sanitizers: []*regexp.Regexp{
		regexp.MustCompile(`bleach\.clean\(`),
		regexp.MustCompile(`shlex\.quote\(`),
		regexp.MustCompile(`html\.escape\(`),
	},
}

// jsPatterns is shared by JavaScript and TypeScript.
var jsPatterns = languagePatterns{
	Sources: []*regexp.Regexp{
		regexp.MustCompile(`req\.(query|body|params)`),
		regexp.MustCompile(`location\.(search|hash)`),
		regexp.MustCompile(`window\.location`),
	},
	Sanitizers: []*regexp.Regexp{
		regexp.MustCompile(`DOMPurify\.sanitize\(`),
		regexp.MustCompile(`encodeURIComponent\(`),
	},
}

var csharpPatterns = languagePatterns{
	Sources: []*regexp.Regexp{
		regexp.MustCompile(`Request\.(QueryString|Form|Params|Cookies)`),
		regexp.MustCompile(`Console\.ReadLine\(`),
	},
	Sanitizers: []*regexp.Regexp{
		regexp.MustCompile(`HttpUtility\.HtmlEncode\(`),
		regexp.MustCompile(`WebUtility\.HtmlEncode\(`),
		regexp.MustCompile(`Encoder\.Default\.Encode\(`),
	},
}

var goPatterns = languagePatterns{
	Sources: []*regexp.Regexp{
		regexp.MustCompile(`os\.Args`),
		regexp.MustCompile(`r\.(URL\.Query\(\)|FormValue\(|PostFormValue\()`),
		regexp.MustCompile(`os\.Getenv\(`),
	},
	Sanitizers: []*regexp.Regexp{
		regexp.MustCompile(`html\.EscapeString\(`),
		regexp.MustCompile(`template\.HTMLEscapeString\(`),
	},
}

var phpPatterns = languagePatterns{
	Sources: []*regexp.Regexp{
		regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE|SERVER)\b`),
	},
	Sanitizers: []*regexp.Regexp{
		regexp.MustCompile(`htmlspecialchars\(`),
		regexp.MustCompile(`htmlentities\(`),
		regexp.MustCompile(`escapeshellarg\(`),
	},
}

var patterns = map[core.Language]languagePatterns{
	core.LangPython:     pythonPatterns,
	core.LangJavaScript: jsPatterns,
	core.LangTypeScript: jsPatterns,
	core.LangCSharp:     csharpPatterns,
	core.LangGo:         goPatterns,
	core.LangPHP:        phpPatterns,
}

// fallbackPatterns preserves the pre-split behavior (one combined
// Python+JS source list) for IR files without a known language — e.g.
// hand-built IR in tests.
var fallbackPatterns = languagePatterns{
	Sources:    append(append([]*regexp.Regexp{}, pythonPatterns.Sources...), jsPatterns.Sources...),
	Sanitizers: append(append([]*regexp.Regexp{}, pythonPatterns.Sanitizers...), jsPatterns.Sanitizers...),
}

// patternsFor returns the taint patterns for a language, falling back to the
// combined Python+JS set when the language has no entry.
func patternsFor(lang core.Language) languagePatterns {
	if p, ok := patterns[lang]; ok {
		return p
	}
	return fallbackPatterns
}

func matchesAny(pats []*regexp.Regexp, text string) bool {
	if text == "" {
		return false
	}
	for _, p := range pats {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}
