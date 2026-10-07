//go:build cgo

package html

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
)

// Template-layer callee names. HTML tag names can never contain a dot, so
// these cannot collide with an element's call node.
const (
	// TemplateExprCallee is one {{ ... }} output expression (Django, Jinja,
	// Nunjucks, Twig, Angular, Vue, Handlebars). Its single literal argument
	// is the expression text with the delimiters and whitespace trimmed.
	TemplateExprCallee = "template.expr"
	// TemplateTagCallee is one {% ... %} block tag; its literal argument is
	// the tag body, e.g. "autoescape off".
	TemplateTagCallee = "template.tag"
	// TemplateCommentExprCallee is a {{ ... }} expression inside an HTML
	// comment of a server-rendered template. The server evaluates it and
	// ships the value to every client inside the comment. Only emitted when
	// the document also contains a {% ... %} tag: client-side frameworks
	// (Angular, Vue) never evaluate interpolations inside comments, so there
	// a commented {{ }} is inert text.
	TemplateCommentExprCallee = "template.comment_expr"
)

var (
	templateExprRe = regexp.MustCompile(`(?s)\{\{(.{0,400}?)\}\}`)
	templateTagRe  = regexp.MustCompile(`(?s)\{%(.{0,400}?)%\}`)
	// Server-side comment and raw/verbatim regions are never rendered as
	// template code, so nothing inside them is an expression.
	templateIgnoreRes = []*regexp.Regexp{
		regexp.MustCompile(`(?s)\{#.*?#\}`),
		regexp.MustCompile(`(?s)\{%-?\s*comment\b.*?%\}.*?\{%-?\s*endcomment\s*-?%\}`),
		regexp.MustCompile(`(?s)\{%-?\s*(?:verbatim|raw)\b.*?%\}.*?\{%-?\s*end(?:verbatim|raw)\s*-?%\}`),
	}
	serverTagRe = regexp.MustCompile(`\{%-?\s*[A-Za-z_]`)
)

type byteRange struct{ start, end int }

func inRanges(rs []byteRange, off int) bool {
	for _, r := range rs {
		if off >= r.start && off < r.end {
			return true
		}
	}
	return false
}

// collectTemplateNodes emits one call node per template expression and
// block tag found in source, so rules can reason about the template layer
// ({{ x|safe }}, {% autoescape off %}) that tree-sitter-html sees only as
// opaque text. The scan is over raw bytes rather than text nodes because the
// same expressions also appear inside attribute values and <script> bodies,
// where they are just as dangerous.
func collectTemplateNodes(rootNode *sitter.Node, source []byte, path string, parent *ir.IRNode) []*ir.IRNode {
	if !strings.Contains(string(source), "{{") && !strings.Contains(string(source), "{%") {
		return nil
	}
	var comments []byteRange
	collectComments(rootNode, &comments)
	var ignore []byteRange
	for _, re := range templateIgnoreRes {
		for _, m := range re.FindAllIndex(source, -1) {
			ignore = append(ignore, byteRange{m[0], m[1]})
		}
	}
	serverRendered := serverTagRe.Match(source)
	lines := lineStarts(source)

	var out []*ir.IRNode
	emit := func(callee, body string, start, end int, inComment bool) {
		call := &ir.IRNode{
			NodeID:   uuid.New().String(),
			Kind:     ir.NodeKindCall,
			Location: byteLoc(lines, path, start, end),
			Parent:   parent,
			Attrs:    map[string]any{"argument_count": 1},
		}
		if inComment {
			call.Attrs["in_comment"] = true
		}
		call.Children = []*ir.IRNode{
			{NodeID: uuid.New().String(), Kind: ir.NodeKindIdentifier, Text: callee, Location: call.Location, Parent: call},
			{NodeID: uuid.New().String(), Kind: ir.NodeKindLiteral, Text: body, Location: call.Location, Parent: call},
		}
		out = append(out, call)
	}
	for _, m := range templateExprRe.FindAllSubmatchIndex(source, -1) {
		if inRanges(ignore, m[0]) {
			continue
		}
		body := trimTemplateBody(string(source[m[2]:m[3]]))
		if body == "" {
			continue
		}
		inComment := inRanges(comments, m[0])
		emit(TemplateExprCallee, body, m[0], m[1], inComment)
		if inComment && serverRendered {
			emit(TemplateCommentExprCallee, body, m[0], m[1], true)
		}
	}
	for _, m := range templateTagRe.FindAllSubmatchIndex(source, -1) {
		if inRanges(ignore, m[0]) {
			continue
		}
		body := trimTemplateBody(string(source[m[2]:m[3]]))
		if body == "" {
			continue
		}
		emit(TemplateTagCallee, body, m[0], m[1], inRanges(comments, m[0]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Location, out[j].Location
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.StartCol < b.StartCol
	})
	return out
}

// trimTemplateBody drops surrounding whitespace and Jinja's whitespace
// control markers ({{- x -}}, {%- tag -%}).
func trimTemplateBody(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "-")
	s = strings.TrimSuffix(s, "-")
	return strings.TrimSpace(s)
}

func collectComments(n *sitter.Node, out *[]byteRange) {
	if n == nil {
		return
	}
	if n.Type() == "comment" {
		*out = append(*out, byteRange{int(n.StartByte()), int(n.EndByte())})
		return
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		collectComments(n.Child(i), out)
	}
}

// lineStarts returns the byte offset at which each line begins.
func lineStarts(src []byte) []int {
	starts := []int{0}
	for i, b := range src {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// byteLoc converts a byte span to a 1-indexed-line location.
func byteLoc(lines []int, path string, start, end int) core.Location {
	pos := func(off int) (int, int) {
		i := sort.Search(len(lines), func(i int) bool { return lines[i] > off }) - 1
		if i < 0 {
			i = 0
		}
		return i + 1, off - lines[i]
	}
	sl, sc := pos(start)
	el, ec := pos(end)
	return core.Location{File: path, StartLine: sl, StartCol: sc, EndLine: el, EndCol: ec}
}
