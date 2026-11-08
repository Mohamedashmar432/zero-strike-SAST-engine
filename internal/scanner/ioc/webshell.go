package ioc

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-003: the classic web shell. Request data is the code or the command,
// not an input to a larger one. Only short files, or files that declare no
// functions, are considered: a shell hidden inside a large application is out
// of scope, and an application's own request handling lives in large files.

const webShellMaxLines = 60

var (
	phpExts  = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".php7": true, ".phar": true, ".inc": true}
	aspExts  = map[string]bool{".asp": true, ".aspx": true, ".ashx": true, ".asa": true, ".cer": true}
	jspExts  = map[string]bool{".jsp": true, ".jspx": true, ".jspf": true}
	superGlb = regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"]HTTP_\w+['"]\s*\]`)
	// A variable function taking request data: $_POST['f']($_POST['a']).
	phpVarFunc = regexp.MustCompile(`@?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*@?\$_(?:GET|POST|REQUEST|COOKIE)`)
	// preg_replace with the /e modifier and request data anywhere in the call.
	pregE = regexp.MustCompile(`(?i)(?:^|[^\w$>:.])@?preg_replace\s*\(\s*(?:'[^']*/[a-zA-Z]*e[a-zA-Z]*'|"[^"]*/[a-zA-Z]*e[a-zA-Z]*")`)
	// Wrappers that only transform request data, peeled before looking at the
	// argument's first token.
	phpWrap = regexp.MustCompile(`(?i)^@?\s*(?:base64_decode|stripslashes|trim|urldecode|rawurldecode|gzinflate|gzuncompress|str_rot13|hex2bin|strrev|pack)\s*\(\s*`)
	phpFunc = regexp.MustCompile(`(?i)\bfunction\s+&?\s*\w+\s*\(|\bclass\s+\w+`)

	aspShell = regexp.MustCompile(`(?i)\b(?:eval|execute|executeglobal)\s*[(\s]\s*(?:request|Request)\b|Process\.Start\s*\([^)]*Request\b`)
	jspShell = regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\s*\.exec\s*\(\s*request\.getParameter|new\s+ProcessBuilder\s*\(\s*request\.getParameter|defineClass\s*\([^)]*request\.getParameter`)
)

func (s *Scanner) webShell(f *file) []core.Finding {
	if f.nonShipped {
		return nil
	}
	switch {
	case phpExts[f.ext]:
		return s.phpShell(f)
	case aspExts[f.ext]:
		return s.simpleShell(f, aspShell, "ASP request data passed to a code or command executor")
	case jspExts[f.ext]:
		return s.simpleShell(f, jspShell, "JSP request parameter passed to a command executor")
	}
	return nil
}

// shortOrFunctionless reports whether the file is small enough, or shaped
// simply enough, to be a standalone shell.
func shortOrFunctionless(f *file, funcRe *regexp.Regexp) bool {
	n := 0
	for _, l := range f.lines {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n < webShellMaxLines || (funcRe != nil && !funcRe.MatchString(f.text))
}

func (s *Scanner) simpleShell(f *file, re *regexp.Regexp, msg string) []core.Finding {
	if !shortOrFunctionless(f, regexp.MustCompile(`(?i)\b(?:function|sub|void|public\s+\w+\s+\w+)\s+\w+\s*\(`)) {
		return nil
	}
	var out []core.Finding
	for _, loc := range re.FindAllStringIndex(f.text, -1) {
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-003", offset: loc[0],
			snippet: f.lines[f.lineAt(loc[0])-1], message: "Web shell shape: " + msg,
			indicator: "web-shell", lang: langForExt(f.ext),
		}))
	}
	return out
}

func (s *Scanner) phpShell(f *file) []core.Finding {
	if !shortOrFunctionless(f, phpFunc) {
		return nil
	}
	var out []core.Finding
	seen := map[int]bool{}
	add := func(off int, msg string) {
		line := f.lineAt(off)
		if seen[line] {
			return
		}
		seen[line] = true
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-003", offset: off,
			snippet: f.lines[line-1], message: "Web shell shape: " + msg,
			indicator: "web-shell", lang: core.LangPHP,
		}))
	}

	for _, loc := range phpVarFunc.FindAllStringIndex(f.text, -1) {
		add(loc[0], "a function chosen by request data is called with request data")
	}
	for _, loc := range s.m.codeSink.FindAllStringSubmatchIndex(f.text, -1) {
		open := loc[1] - 1
		for open > loc[0] && f.text[open] != '(' {
			open--
		}
		if args, _, ok := callArgs(f.text, open); ok && superGlb.MatchString(args) {
			add(loc[2], f.text[loc[2]:loc[3]]+"() runs request data")
		}
	}
	for _, loc := range s.m.cmdSink.FindAllStringSubmatchIndex(f.text, -1) {
		open := loc[1] - 1
		for open > loc[0] && f.text[open] != '(' {
			open--
		}
		args, _, ok := callArgs(f.text, open)
		if !ok {
			continue
		}
		if startsWithRequest(args) {
			add(loc[2], f.text[loc[2]:loc[3]]+"() executes request data as the command")
		}
	}
	for _, loc := range pregE.FindAllStringIndex(f.text, -1) {
		open := strings.IndexByte(f.text[loc[0]:], '(') + loc[0]
		if args, _, ok := callArgs(f.text, open); ok && superGlb.MatchString(args) {
			add(loc[0], "preg_replace with the /e modifier evaluates request data")
		}
	}
	return out
}

// startsWithRequest reports whether a call argument is request data, possibly
// wrapped in transform-only functions, optionally followed by a concatenation
// (`$_GET['c'] . ' 2>&1'`).
func startsWithRequest(args string) bool {
	a := strings.TrimSpace(args)
	for i := 0; i < 4; i++ {
		loc := phpWrap.FindStringIndex(a)
		if loc == nil {
			break
		}
		a = a[loc[1]:]
	}
	a = strings.TrimLeft(a, "@ \t\r\n")
	loc := superGlb.FindStringIndex(a)
	return loc != nil && loc[0] == 0
}
