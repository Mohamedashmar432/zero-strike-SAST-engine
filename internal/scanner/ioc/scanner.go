// Package ioc is the indicator-of-compromise scanner: it looks for signs that
// a repository already carries malicious code (install-time downloaders,
// obfuscated loaders, web shells, reverse shells, miners, exfiltration
// endpoints, feed matches, compromised workflow actions) rather than for
// weaknesses a developer wrote by mistake. Offline and deterministic; only
// enabled with --enable-ioc.
package ioc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// Options configures a Scanner.
type Options struct {
	Root     string // scan root; paths are classified relative to it
	FeedPath string // optional organisation IOC feed (ZS-IOC-007)
}

// Scanner implements scanner.Scanner for the IOC rules.
type Scanner struct {
	root string
	m    *matchers
	feed *feed
}

// New builds a Scanner. It fails on an unreadable or malformed feed rather
// than scanning without the indicators the user asked for.
func New(opts Options) (*Scanner, error) {
	m, err := loadMatchers()
	if err != nil {
		return nil, err
	}
	s := &Scanner{root: opts.Root, m: m}
	if opts.FeedPath != "" {
		f, err := loadFeed(opts.FeedPath)
		if err != nil {
			return nil, err
		}
		s.feed = f
	}
	return s, nil
}

func (s *Scanner) Name() string { return "ioc" }

// Accepts takes every file except asset-data entries, which are for the
// secrets scanner only. Binary files are accepted only for the SHA-256 feed
// check; every text rule skips them.
func (s *Scanner) Accepts(entry walker.FileEntry) bool {
	if entry.AssetData {
		return false
	}
	return !entry.IsBinary || s.feed != nil
}

func (s *Scanner) Scan(ctx context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	var out []core.Finding
	var diags []analyzer.Diagnostic
	for _, entry := range files {
		if ctx.Err() != nil {
			break
		}
		data, err := os.ReadFile(entry.Path)
		if err != nil {
			diags = append(diags, analyzer.Diagnostic{
				Severity: "warning",
				Message:  fmt.Sprintf("ioc: failed to read %s: %v", entry.Path, err),
				Location: &core.Location{File: entry.Path},
			})
			continue
		}
		out = append(out, s.scanFile(entry, data)...)
	}
	return out, diags, nil
}

// scanFile runs every rule that applies to one file.
func (s *Scanner) scanFile(entry walker.FileEntry, data []byte) []core.Finding {
	f := newFile(s, entry, data)
	var out []core.Finding
	if !entry.IsBinary {
		out = append(out, s.installHooks(f)...)
		out = append(out, s.encodedPayload(f)...)
		out = append(out, s.webShell(f)...)
		out = append(out, s.reverseShell(f)...)
		out = append(out, s.miner(f)...)
		out = append(out, s.exfil(f)...)
		out = append(out, s.workflowActions(f)...)
	}
	if s.feed != nil {
		out = append(out, s.feedMatches(f, data)...)
	}
	return out
}

// file is one scanned file with the derived facts every rule shares.
type file struct {
	path  string
	rel   string // forward-slash path relative to the scan root
	base  string // lower-case base name
	ext   string // lower-case extension with dot
	role  walker.FileRole
	text  string
	lines []string
	// nonShipped: test, fixture, documentation or vendored material. The rules
	// that a legitimate project may trip over (002, 004, 005, 006) skip it.
	nonShipped bool
	lineStarts []int
}

func newFile(s *Scanner, e walker.FileEntry, data []byte) *file {
	rel := e.Path
	if s.root != "" {
		if r, err := filepath.Rel(s.root, e.Path); err == nil {
			rel = r
		}
	}
	rel = filepath.ToSlash(rel)
	f := &file{
		path: e.Path, rel: rel,
		base: strings.ToLower(filepath.Base(rel)),
		ext:  strings.ToLower(filepath.Ext(rel)),
		role: e.Role,
	}
	if !e.IsBinary {
		f.text = string(data)
		f.lines = strings.Split(f.text, "\n")
		off := 0
		f.lineStarts = make([]int, len(f.lines))
		for i, l := range f.lines {
			f.lineStarts[i] = off
			off += len(l) + 1
		}
	}
	f.nonShipped = e.Role == walker.RoleTest || isDocPath(rel) || isVendorPath(rel)
	return f
}

// lineAt returns the 1-based line number of byte offset off.
func (f *file) lineAt(off int) int {
	lo, hi := 0, len(f.lineStarts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if f.lineStarts[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

func (f *file) colAt(off int) int {
	l := f.lineAt(off)
	return off - f.lineStarts[l-1] + 1
}

var docDirs = map[string]bool{
	"docs": true, "doc": true, "documentation": true,
	"example": true, "examples": true, "sample": true, "samples": true,
}

var vendorDirs = map[string]bool{
	"vendor": true, "node_modules": true, "third_party": true, "bower_components": true,
}

var docExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".txt": true, ".rdoc": true,
}

func segments(rel string) []string {
	parts := strings.Split(strings.ReplaceAll(rel, "\\", "/"), "/")
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	return parts
}

func isDocPath(rel string) bool {
	parts := segments(rel)
	for _, p := range parts[:len(parts)-1] {
		if docDirs[p] {
			return true
		}
	}
	return docExts[filepath.Ext(parts[len(parts)-1])]
}

func isVendorPath(rel string) bool {
	parts := segments(rel)
	for _, p := range parts[:len(parts)-1] {
		if vendorDirs[p] {
			return true
		}
	}
	return false
}

// hit describes one rule match before it becomes a finding.
type hit struct {
	rule      string
	offset    int    // byte offset in f.text; negative means use line
	line      int    // 1-based, used when offset < 0
	snippet   string // the matched line or statement, untruncated
	message   string
	indicator string
	conf      core.Confidence
	lang      core.Language
	extra     map[string]string
}

func (f *file) finding(h hit) core.Finding {
	r := ruleByID(h.rule)
	line, col := h.line, 1
	if h.offset >= 0 {
		line, col = f.lineAt(h.offset), f.colAt(h.offset)
	}
	snippet := strings.TrimSpace(h.snippet)
	norm := strings.Join(strings.Fields(snippet), " ")
	sum := sha256.Sum256([]byte(r.ID + "|" + f.rel + "|" + h.indicator + "|" + norm))
	meta := map[string]string{"ioc": r.Short}
	if h.indicator != "" {
		meta["indicator"] = h.indicator
	}
	for k, v := range h.extra {
		meta[k] = v
	}
	conf := h.conf
	if conf == "" {
		conf = core.ConfidenceHigh
	}
	lang := h.lang
	if lang == "" {
		lang = core.LangUnknown
	}
	return core.Finding{
		ID:          uuid.New().String(),
		RuleID:      r.ID,
		RuleName:    r.Name,
		Category:    Category,
		Severity:    r.Severity,
		Confidence:  conf,
		Message:     h.message,
		Location:    core.Location{File: f.path, StartLine: line, EndLine: line, StartCol: col},
		Language:    lang,
		Evidence:    []core.Evidence{{Snippet: truncate(snippet, 200), StartLine: line, EndLine: line}},
		CWE:         []string{r.CWE},
		Metadata:    meta,
		Fingerprint: hex.EncodeToString(sum[:])[:16],
		Kind:        core.FindingKindIOC,
		Rationale:   r.Rationale,
		Description: r.Description,
		Remediation: r.Remediation,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func langForExt(ext string) core.Language {
	switch ext {
	case ".js", ".mjs", ".cjs", ".jsx":
		return core.LangJavaScript
	case ".ts", ".tsx":
		return core.LangTypeScript
	case ".php", ".phtml", ".php5", ".phar", ".inc":
		return core.LangPHP
	case ".py":
		return core.LangPython
	case ".java", ".jsp", ".jspx":
		return core.LangJava
	case ".cs", ".aspx", ".ashx", ".asp":
		return core.LangCSharp
	}
	return core.LangUnknown
}
