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
	// TemplateRawExprCallee is one EJS <%- expr %> raw (unescaped) output
	// tag; its literal argument is the expression text. <%= expr %> escapes
	// and is not emitted. Only .ejs files are scanned for it, because in a
	// JSP or ERB file <%- is a comment or trim marker, not an output tag.
	TemplateRawExprCallee = "template.raw_expr"
	// TemplateScriptExprCallee is the first {{ ... }} expression inside a
	// <script> element of a server-rendered template (one that also holds a
	// {% ... %} tag). The server substitutes the value into JavaScript
	// source, where HTML escaping does not make a bare value safe. An
	// expression that is the whole content of a quoted JS string is skipped
	// (auto-escaping entity-encodes the quote). One node per script element:
	// the first expression in code position stands for the block.
	TemplateScriptExprCallee = "template.script_expr"
	// TemplateFormNoCSRFCallee is a <form> that submits with a state-changing
	// method (POST, PUT, PATCH, DELETE) inside a server-rendered template,
	// with no {% csrf_token %} tag before its closing </form>. Its literal
	// argument is the form's opening tag.
	TemplateFormNoCSRFCallee = "template.form_no_csrf"
	// TemplateFormBadCSRFCallee is the same form when it carries something
	// shaped like a csrf tag but malformed so it never renders as one
	// ("{ % csrf_token % }" with stray spaces inside the braces). Django
	// prints it as literal text and the form goes out unprotected.
	TemplateFormBadCSRFCallee = "template.form_bad_csrf"
	// TemplateRawOutputCallee is an unencoded output tag of a server-rendered
	// view: Razor @Html.Raw(expr), Blade {!! expr !!} and <?= expr ?>, Web
	// Forms <%= expr %> (Handlebars {{{ expr }}} is ZS-HTML-023, on template.expr). Its literal argument is the
	// expression text. The encoding forms (@expr, {{ expr }}, <%: expr %>) are
	// not emitted. Each form is only recognised in its own file type.
	TemplateRawOutputCallee = "template.raw_output"
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
	// A <form> whose method attribute is not GET, and a Django csrf_token tag
	// (the tag name may be followed by args and a "-" whitespace marker).
	formOpenRe   = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	formMethodRe = regexp.MustCompile(`(?is)\bmethod\s*=\s*["']?\s*(post|put|patch|delete)\b`)
	badCSRFRe    = regexp.MustCompile(`(?i)\{\s+%[^}\n]{0,40}cs?r?s?f[^}\n]{0,40}%\s*\}|\{\s*%[^}\n]{0,40}cs?r?s?f[^}\n]{0,40}%\s+\}`)
	csrfTagRe    = regexp.MustCompile(`\{%-?\s*csrf_token\b`)
	serverTagRe = regexp.MustCompile(`\{%-?\s*[A-Za-z_]`)
	// EJS raw output; a trailing -%> trim marker is excluded from the body.
	ejsRawExprRe = regexp.MustCompile(`(?s)<%-(.{0,400}?)-?%>`)

	// Unencoded output tags of the other server-side view engines.
	bladeRawRe   = regexp.MustCompile(`(?s)\{!!(.{0,400}?)!!\}`)
	phpEchoRe    = regexp.MustCompile(`(?s)<\?=(.{0,400}?)\?>`)
	aspxRawRe    = regexp.MustCompile(`(?s)<%=(.{0,400}?)%>`)
	razorRawRe   = regexp.MustCompile(`@Html\.Raw\(`)
	razorCmtRe   = regexp.MustCompile(`(?s)@\*.*?\*@`)
	bladeCmtRe   = regexp.MustCompile(`(?s)\{\{--.*?--\}\}`)
	aspxCmtRe    = regexp.MustCompile(`(?s)<%--.*?--%>`)
)

// rawOutputKind says which unencoded-output syntaxes apply to a file.
type rawOutputKind struct{ razor, blade, aspx bool }

func rawOutputKindOf(path string) rawOutputKind {
	p := strings.ToLower(path)
	return rawOutputKind{
		razor: strings.HasSuffix(p, ".cshtml") || strings.HasSuffix(p, ".razor"),
		blade: strings.HasSuffix(p, ".blade.php"),
		aspx:  strings.HasSuffix(p, ".aspx") || strings.HasSuffix(p, ".ascx") || strings.HasSuffix(p, ".master"),
	}
}

// balancedParen returns the index just past the ")" that closes the "(" at
// source[open], skipping string literals, or -1 when it does not close on the
// same expression (bounded, so a stray "(" cannot swallow the file).
func balancedParen(source []byte, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(source) && i < open+400; i++ {
		c := source[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

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
	ejs := strings.HasSuffix(strings.ToLower(path), ".ejs") && strings.Contains(string(source), "<%-")
	raw := rawOutputKindOf(path)
	hasRaw := (raw.razor && strings.Contains(string(source), "@Html.Raw(")) ||
		(raw.blade && (strings.Contains(string(source), "{!!") || strings.Contains(string(source), "<?="))) ||
		(raw.aspx && strings.Contains(string(source), "<%="))
	if !ejs && !hasRaw && !strings.Contains(string(source), "{{") && !strings.Contains(string(source), "{%") {
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
	if raw.razor || raw.blade || raw.aspx {
		for _, re := range []*regexp.Regexp{razorCmtRe, bladeCmtRe, aspxCmtRe} {
			for _, m := range re.FindAllIndex(source, -1) {
				ignore = append(ignore, byteRange{m[0], m[1]})
			}
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
	if ejs {
		for _, m := range ejsRawExprRe.FindAllSubmatchIndex(source, -1) {
			body := trimTemplateBody(string(source[m[2]:m[3]]))
			// <%-- is a comment form, never output (the check is on the raw
			// byte because trimTemplateBody strips a leading "-").
			if body == "" || source[m[2]] == '-' {
				continue
			}
			emit(TemplateRawExprCallee, body, m[0], m[1], inRanges(comments, m[0]))
		}
	}
	rawEmit := func(start, end int, body string) {
		body = strings.TrimSpace(body)
		if body == "" || inRanges(ignore, start) {
			return
		}
		emit(TemplateRawOutputCallee, body, start, end, false)
	}
	switch {
	case raw.razor:
		for _, m := range razorRawRe.FindAllIndex(source, -1) {
			if end := balancedParen(source, m[1]-1); end > 0 {
				rawEmit(m[0], end, string(source[m[1]:end-1]))
			}
		}
	case raw.blade:
		for _, m := range bladeRawRe.FindAllSubmatchIndex(source, -1) {
			rawEmit(m[0], m[1], string(source[m[2]:m[3]]))
		}
		for _, m := range phpEchoRe.FindAllSubmatchIndex(source, -1) {
			rawEmit(m[0], m[1], string(source[m[2]:m[3]]))
		}
	case raw.aspx:
		for _, m := range aspxRawRe.FindAllSubmatchIndex(source, -1) {
			rawEmit(m[0], m[1], string(source[m[2]:m[3]]))
		}
	}
	if serverRendered {
		var scripts []byteRange
		collectScriptBodies(rootNode, &scripts)
		for _, sr := range scripts {
			for _, m := range templateExprRe.FindAllSubmatchIndex(source[sr.start:sr.end], -1) {
				start, end := sr.start+m[0], sr.start+m[1]
				body := trimTemplateBody(string(source[sr.start+m[2] : sr.start+m[3]]))
				if body == "" || inRanges(ignore, start) || inJSString(source, start) {
					continue
				}
				emit(TemplateScriptExprCallee, body, start, end, false)
				break
			}
		}
		for _, m := range formOpenRe.FindAllIndex(source, -1) {
			tag := string(source[m[0]:m[1]])
			if !formMethodRe.MatchString(tag) || inRanges(comments, m[0]) {
				continue
			}
			rest := source[m[1]:]
			if i := strings.Index(strings.ToLower(string(rest)), "</form"); i >= 0 {
				rest = rest[:i]
			}
			if csrfTagRe.Match(rest) {
				continue
			}
			callee := TemplateFormNoCSRFCallee
			if badCSRFRe.Match(rest) {
				callee = TemplateFormBadCSRFCallee
			}
			emit(callee, tag, m[0], m[1], false)
		}
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

// inJSString reports whether the expression starting at start sits inside a
// quoted JavaScript string on its own line. Django and Jinja auto-escaping
// turns quotes into entities, so such a value cannot break out of the string;
// only an expression in code position (a bare identifier, array element or
// statement) is injectable. Quote state is tracked from the start of the line
// (a string that spans lines is rare in inline scripts).
func inJSString(src []byte, start int) bool {
	ls := start
	for ls > 0 && src[ls-1] != '\n' {
		ls--
	}
	var open byte
	for i := ls; i < start; i++ {
		c := src[i]
		switch {
		case open != 0 && c == '\\':
			i++
		case open != 0 && c == open:
			open = 0
		case open == 0 && (c == '\'' || c == '"' || c == '`'):
			open = c
		}
	}
	return open != 0
}

// collectScriptBodies records the byte range of every <script> element's body.
func collectScriptBodies(n *sitter.Node, out *[]byteRange) {
	if n == nil {
		return
	}
	if n.Type() == "script_element" {
		for i := 0; i < int(n.ChildCount()); i++ {
			if c := n.Child(i); c.Type() == "raw_text" {
				*out = append(*out, byteRange{int(c.StartByte()), int(c.EndByte())})
			}
		}
		return
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		collectScriptBodies(n.Child(i), out)
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
