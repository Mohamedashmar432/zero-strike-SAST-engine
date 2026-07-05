package detector

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/zerostrike/scanner/internal/core"
)

// extMap maps lowercase file extensions (including the leading dot) to
// their canonical language. It is package-level and never mutated.
var extMap = map[string]core.Language{
	".py":   core.LangPython,
	".pyw":  core.LangPython,
	".js":   core.LangJavaScript,
	".mjs":  core.LangJavaScript,
	".cjs":  core.LangJavaScript,
	".jsx":  core.LangJavaScript,
	".ts":   core.LangTypeScript,
	".tsx":  core.LangTypeScript,
	".mts":  core.LangTypeScript,
	".cts":  core.LangTypeScript,
	".cs":   core.LangCSharp,
	".go":   core.LangGo,
	".php":  core.LangPHP,
	".java": core.LangJava,
}

// shebangMap maps known shebang interpreter strings to their language.
// Only the interpreter portion (after "#!") is stored, without arguments,
// so we match via prefix/exact checks in detectShebang.
var shebangMap = []struct {
	prefix string
	lang   core.Language
}{
	{"#!/usr/bin/python3", core.LangPython},
	{"#!/usr/bin/python", core.LangPython},
	{"#!/usr/bin/env python3", core.LangPython},
	{"#!/usr/bin/env python", core.LangPython},
	{"#!/usr/bin/node", core.LangJavaScript},
	{"#!/usr/bin/env node", core.LangJavaScript},
}

// detector is the concrete implementation of Detector.
type detector struct{}

// Detect identifies the language of a source file.
//
//  1. Lowercase extension lookup (fast path).
//  2. Shebang line matching (fallback).
//  3. core.LangUnknown when neither strategy matches.
func (d *detector) Detect(path string, content []byte) core.Language {
	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := extMap[ext]; ok {
		return lang
	}

	if len(content) > 0 {
		if lang := detectShebang(content); lang != core.LangUnknown {
			return lang
		}
	}

	return core.LangUnknown
}

// detectShebang reads the first line of content and matches it against
// known shebang patterns. Returns core.LangUnknown when no match is found.
func detectShebang(content []byte) core.Language {
	// Extract first line only.
	firstLine := content
	if idx := bytes.IndexByte(content, '\n'); idx >= 0 {
		firstLine = content[:idx]
	}

	line := strings.TrimRight(string(firstLine), "\r")

	if !strings.HasPrefix(line, "#!") {
		return core.LangUnknown
	}

	for _, entry := range shebangMap {
		// Match exactly or followed by whitespace/end-of-line so that
		// "#!/usr/bin/python3" does not match "#!/usr/bin/python".
		if line == entry.prefix || strings.HasPrefix(line, entry.prefix+" ") {
			return entry.lang
		}
	}

	return core.LangUnknown
}
