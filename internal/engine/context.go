package engine

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

// fileCtx is the per-file state matchNode/evalFilter consult: the taint sets,
// the language, the Python import table, and lazily built def-use indexes for
// the constant-path and written-file filters. One is built per Match call and
// never shared across goroutines.
type fileCtx struct {
	tainted map[string]bool
	weak    map[string]bool
	lang    core.Language
	root    *ir.IRNode
	aliases map[string]string // Python import table

	indexed bool
	assigns map[string][]*ir.IRNode // simple-name LHS -> assignment nodes
	asBinds map[string][]*ir.IRNode // `with X as name` -> as_pattern nodes
	bound   map[string]bool         // names bound by params, loops, tuple unpacking, augmented assignment
	constMu map[string]int8         // memo: 1 constant, -1 not, 0 in progress

	// consts maps module-level names bound exactly once, to a literal, to that
	// literal's value, so argument_literal_matches sees through a named
	// constant. See moduleConstants.
	consts map[string]string

	// JS/TS only: module bindings and object-literal initializers that some
	// filters resolve through (see jsfamily.go).
	jsOnce   bool
	bindings map[string]string       // local name -> canonical module path
	objDecls map[string][]*ir.IRNode // local name -> object-literal initializers

	lastNode *ir.IRNode // memo for callee()
	lastText string
}

func newFileCtx(f *ir.IRFile, tainted, weak map[string]bool) *fileCtx {
	fc := &fileCtx{tainted: tainted, weak: weak, lang: f.Language, root: f.Root, consts: moduleConstants(f.Root)}
	if f.Language == core.LangPython && f.Root != nil {
		fc.aliases, _ = f.Root.Attrs["import_aliases"].(map[string]string)
	}
	return fc
}

// canonicalAlias resolves the first segment of a dotted callee through the
// file's import table: with `from hashlib import md5`, "md5" becomes
// "hashlib.md5"; with `import xml.etree.ElementTree as ET`, "ET.fromstring"
// becomes "xml.etree.ElementTree.fromstring". Returns text unchanged when
// nothing applies (every non-Python file).
func (fc *fileCtx) canonicalAlias(text string) string {
	if len(fc.aliases) == 0 || text == "" {
		return text
	}
	head, rest := text, ""
	if i := strings.IndexByte(text, '.'); i >= 0 {
		head, rest = text[:i], text[i:]
	}
	if c, ok := fc.aliases[head]; ok {
		return c + rest
	}
	return text
}

// evalContextFilters evaluates the filters that need more than the node
// itself: the callee's canonical form, the decorator stack, the enclosing
// function, and local def-use for path constant folding.
func evalContextFilters(f rules.Filter, n *ir.IRNode, fc *fileCtx) bool {
	if f.CalleeMatches != "" {
		if n.Kind != ir.NodeKindCall {
			return false
		}
		text := calleeText(n)
		canon := fc.canonicalAlias(text)
		if !regexMatches(f.CalleeMatches, text) && !(canon != text && regexMatches(f.CalleeMatches, canon)) {
			return false
		}
	}
	if f.DecoratorStackMatches != "" {
		stack, _ := n.Attrs["decorator_stack"].([]string)
		if n.Kind != ir.NodeKindDecorator {
			stack, _ = n.Attrs["decorators"].([]string)
		}
		found := false
		for _, d := range stack {
			if regexMatches(f.DecoratorStackMatches, d) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.EnclosingFunctionMatches != "" {
		fn := enclosingFunction(n)
		if fn == nil {
			return false
		}
		name, _ := fn.Attrs["function_name"].(string)
		if !regexMatches(f.EnclosingFunctionMatches, name) {
			return false
		}
	}
	if f.ArgumentNotConstant != nil {
		args := argumentNodes(n)
		i := *f.ArgumentNotConstant
		if i < 0 {
			i += len(args)
		}
		if i >= 0 && i < len(args) && fc.isConstant(args[i]) {
			return false
		}
	}
	if f.WrittenFileMatches != "" {
		if fc.lang != core.LangPython || n.Kind != ir.NodeKindCall {
			return false
		}
		shape, ok := fc.writtenFileShape(n)
		if !ok || !regexMatches(f.WrittenFileMatches, shape) {
			return false
		}
	}
	return true
}

// enclosingFunction returns the nearest function_def ancestor of n, or nil.
func enclosingFunction(n *ir.IRNode) *ir.IRNode {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Kind == ir.NodeKindFunction {
			return p
		}
	}
	return nil
}

// index builds the def-use tables on first use. Only simple-name
// assignments are recorded as definitions; every other way a name can be
// bound (parameter, loop target, tuple unpacking, augmented assignment)
// marks it as never constant, so folding stays conservative.
func (fc *fileCtx) index() {
	if fc.indexed {
		return
	}
	fc.indexed = true
	fc.assigns = make(map[string][]*ir.IRNode)
	fc.asBinds = make(map[string][]*ir.IRNode)
	fc.bound = make(map[string]bool)
	fc.constMu = make(map[string]int8)
	if fc.root == nil {
		return
	}
	ir.Walk(fc.root, func(n *ir.IRNode) bool {
		switch n.Kind {
		case ir.NodeKindAssignment:
			lhs, _ := n.Attrs["lhs"].(string)
			lhs = strings.TrimSpace(lhs)
			if aug, _ := n.Attrs["augmented"].(bool); aug {
				fc.bound[lhs] = true
				return true
			}
			if isSimpleName(lhs) {
				fc.assigns[lhs] = append(fc.assigns[lhs], n)
			} else {
				for _, part := range strings.Split(lhs, ",") {
					if p := strings.TrimSpace(part); isSimpleName(p) {
						fc.bound[p] = true
					}
				}
			}
		case ir.NodeKindFunction:
			params, _ := n.Attrs["parameters"].([]string)
			for _, p := range params {
				fc.bound[p] = true
			}
		case ir.NodeKindFor:
			for _, c := range n.Children {
				if c.Kind == ir.NodeKindUnknown && len(c.Children) == 0 && strings.TrimSpace(c.Text) == "in" {
					break
				}
				if c.Kind == ir.NodeKindIdentifier {
					fc.bound[c.Text] = true
				}
				for _, d := range ir.Descendants(c) {
					if d.Kind == ir.NodeKindIdentifier {
						fc.bound[d.Text] = true
					}
				}
			}
		default:
			if name, _ := n.Attrs["as_name"].(string); name != "" {
				fc.asBinds[name] = append(fc.asBinds[name], n)
				fc.bound[name] = true
			}
		}
		return true
	})
}

func isSimpleName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// isConstant reports whether an argument is a compile-time constant: a
// literal with no interpolated expression in any language, plus Python's
// path folding (see isConstPath).
func (fc *fileCtx) isConstant(n *ir.IRNode) bool {
	if fc.lang == core.LangPython {
		return fc.isConstPath(n, 0)
	}
	if n.Kind != ir.NodeKindLiteral {
		return false
	}
	for _, d := range ir.Descendants(n) {
		if d.Kind == ir.NodeKindIdentifier || d.Kind == ir.NodeKindCall || d.Kind == ir.NodeKindAttribute {
			return false
		}
	}
	return true
}

// constPathFuncs are the path builders whose result is constant when every
// argument is. Keyed by import-canonical callee text.
var constPathFuncs = map[string]bool{
	"os.path.join": true, "os.path.dirname": true, "os.path.abspath": true,
	"os.path.realpath": true, "os.path.normpath": true, "os.path.basename": true,
	"pathlib.Path": true, "pathlib.PurePath": true, "pathlib.PurePosixPath": true,
	"pathlib.PureWindowsPath": true, "pathlib.PosixPath": true, "pathlib.WindowsPath": true,
	"str": true,
}

// constPathMethods are Path methods/properties that keep a constant receiver
// constant.
var constPathMethods = map[string]bool{
	"resolve": true, "absolute": true, "joinpath": true, "with_name": true,
	"with_suffix": true, "parent": true, "name": true, "stem": true, "suffix": true,
}

// isConstPath reports whether expression n can only ever evaluate to one
// fixed path: literals, __file__, and the path builders above applied to
// constants, followed through local variables whose every assignment in the
// file is constant. A path that cannot be influenced by input cannot be
// traversed, which is the whole premise of the path-traversal rules.
func (fc *fileCtx) isConstPath(n *ir.IRNode, depth int) bool {
	if n == nil || depth > 12 {
		return false
	}
	switch n.Kind {
	case ir.NodeKindLiteral:
		// An f-string is constant only when every interpolated name is.
		for _, d := range ir.Descendants(n) {
			if d.Kind == ir.NodeKindCall {
				return false
			}
			if d.Kind == ir.NodeKindIdentifier && !fc.isConstName(d.Text, depth+1) {
				return false
			}
		}
		return true
	case ir.NodeKindIdentifier:
		return fc.isConstName(n.Text, depth+1)
	case ir.NodeKindAttribute:
		if len(n.Children) < 2 {
			return false
		}
		last := n.Children[len(n.Children)-1]
		if last.Kind != ir.NodeKindIdentifier || !constPathMethods[last.Text] {
			return false
		}
		return fc.isConstPath(n.Children[0], depth+1)
	case ir.NodeKindCall:
		if len(n.Children) == 0 {
			return false
		}
		callee := n.Children[0]
		switch {
		case constPathFuncs[fc.canonicalAlias(calleeText(n))] && callee.Kind != ir.NodeKindCall:
		case callee.Kind == ir.NodeKindAttribute && len(callee.Children) >= 2:
			m := callee.Children[len(callee.Children)-1]
			if m.Kind != ir.NodeKindIdentifier || !constPathMethods[m.Text] || !fc.isConstPath(callee.Children[0], depth+1) {
				return false
			}
		default:
			return false
		}
		for _, a := range argumentNodes(n) {
			if !fc.isConstPath(a, depth+1) {
				return false
			}
		}
		return true
	case ir.NodeKindBinaryOp:
		return fc.allOperandsConst(n, depth)
	case ir.NodeKindUnknown:
		// Parenthesized expressions and implicit string concatenation.
		if len(n.Children) == 0 {
			return false
		}
		return fc.allOperandsConst(n, depth)
	}
	return false
}

// allOperandsConst checks every non-punctuation child of an operator or
// grouping node.
func (fc *fileCtx) allOperandsConst(n *ir.IRNode, depth int) bool {
	seen := false
	for _, c := range n.Children {
		if c.Kind == ir.NodeKindUnknown && len(c.Children) == 0 {
			continue // operator / punctuation token
		}
		if !fc.isConstPath(c, depth+1) {
			return false
		}
		seen = true
	}
	return seen
}

func (fc *fileCtx) isConstName(name string, depth int) bool {
	if name == "__file__" {
		return true
	}
	fc.index()
	switch fc.constMu[name] {
	case 1:
		return true
	case -1:
		return false
	}
	if fc.bound[name] {
		fc.constMu[name] = -1
		return false
	}
	defs := fc.assigns[name]
	if len(defs) == 0 {
		fc.constMu[name] = -1
		return false
	}
	fc.constMu[name] = -1 // cycle guard: x = x + "a" is not constant
	for _, d := range defs {
		if len(d.Children) == 0 || !fc.isConstPath(d.Children[len(d.Children)-1], depth+1) {
			return false
		}
	}
	fc.constMu[name] = 1
	return true
}

// writtenFileShape resolves the file a write call (recv.write(...),
// Path(p).write_text(...)) writes to and returns its path shape. ok is false
// when the target cannot be resolved or is opened read-only.
func (fc *fileCtx) writtenFileShape(call *ir.IRNode) (string, bool) {
	if len(call.Children) == 0 {
		return "", false
	}
	callee := call.Children[0]
	if callee.Kind != ir.NodeKindAttribute || len(callee.Children) < 2 {
		return "", false
	}
	return fc.fileTargetShape(callee.Children[0], call, 0)
}

// fileTargetShape resolves an expression that should evaluate to a writable
// file handle (or a Path) to the shape of its path.
func (fc *fileCtx) fileTargetShape(recv, use *ir.IRNode, depth int) (string, bool) {
	if recv == nil || depth > 3 {
		return "", false
	}
	switch recv.Kind {
	case ir.NodeKindCall:
		args := argumentNodes(recv)
		switch fc.canonicalAlias(calleeText(recv)) {
		case "open", "io.open", "codecs.open", "builtins.open":
			if len(args) == 0 || !openModeWrites(recv, args) {
				return "", false
			}
			return fc.pathShape(args[0], recv, 0), true
		case "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath":
			parts := make([]string, 0, len(args))
			for _, a := range args {
				parts = append(parts, fc.pathShape(a, recv, 0))
			}
			return strings.Join(parts, "/"), len(parts) > 0
		}
	case ir.NodeKindIdentifier:
		def := fc.nearestDefinition(recv.Text, use)
		if def == nil {
			return "", false
		}
		if def.Kind == ir.NodeKindAssignment {
			return fc.fileTargetShape(def.Children[len(def.Children)-1], def, depth+1)
		}
		// `with open(p, "w") as f`: the as_pattern's first child is the value.
		if len(def.Children) > 0 {
			return fc.fileTargetShape(def.Children[0], def, depth+1)
		}
	}
	return "", false
}

// openModeWrites reports whether an open() call's mode (second positional
// argument or mode= keyword) can write. An absent mode is "r"; a non-literal
// mode is assumed to write, since it cannot be ruled out.
func openModeWrites(call *ir.IRNode, args []*ir.IRNode) bool {
	mode, known := "r", true
	for _, a := range args {
		if a.Kind == ir.NodeKindKeywordArg {
			if name, _ := a.Attrs["kwarg_name"].(string); name == "mode" {
				v, _ := a.Attrs["kwarg_value"].(string)
				mode, known = literalText(v)
			}
		}
	}
	if len(args) > 1 && args[1].Kind != ir.NodeKindKeywordArg {
		if args[1].Kind == ir.NodeKindLiteral {
			mode = args[1].Text
		} else {
			known = false
		}
	}
	return !known || strings.ContainsAny(mode, "wax+")
}

// literalText unquotes a Python string literal's source text; ok is false
// for anything that is not a plain quoted literal.
func literalText(src string) (string, bool) {
	src = strings.TrimSpace(src)
	if len(src) >= 2 && (src[0] == '"' || src[0] == '\'') && src[len(src)-1] == src[0] {
		return src[1 : len(src)-1], true
	}
	return "", false
}

// nearestDefinition returns the binding of name that reaches use: the last
// simple assignment or `with ... as name` at or before use's line, preferring
// one in use's own function.
func (fc *fileCtx) nearestDefinition(name string, use *ir.IRNode) *ir.IRNode {
	fc.index()
	fn := enclosingFunction(use)
	var best, bestAny *ir.IRNode
	consider := func(d *ir.IRNode) {
		if d.Location.StartLine > use.Location.StartLine {
			return
		}
		if bestAny == nil || d.Location.StartLine >= bestAny.Location.StartLine {
			bestAny = d
		}
		if enclosingFunction(d) == fn && (best == nil || d.Location.StartLine >= best.Location.StartLine) {
			best = d
		}
	}
	for _, d := range fc.assigns[name] {
		consider(d)
	}
	for _, d := range fc.asBinds[name] {
		consider(d)
	}
	if best != nil {
		return best
	}
	return bestAny
}

var fstringField = regexp.MustCompile(`\{[^{}]*\}`)

// pathShape renders a path expression as text with every part that is not a
// literal replaced by "*": os.path.join(BASE, f"templates/{id}.html") becomes
// "*/templates/*.html". It exists so a rule can ask what kind of file is
// written (a .py module, a template) without the path being constant.
func (fc *fileCtx) pathShape(n, use *ir.IRNode, depth int) string {
	if n == nil || depth > 8 {
		return "*"
	}
	switch n.Kind {
	case ir.NodeKindLiteral:
		return stringShape(n.Text)
	case ir.NodeKindIdentifier:
		if def := fc.nearestDefinition(n.Text, use); def != nil && def.Kind == ir.NodeKindAssignment && len(def.Children) > 0 {
			return fc.pathShape(def.Children[len(def.Children)-1], def, depth+1)
		}
		return "*"
	case ir.NodeKindCall:
		args := argumentNodes(n)
		switch fc.canonicalAlias(calleeText(n)) {
		case "os.path.join", "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath":
			parts := make([]string, 0, len(args))
			for _, a := range args {
				parts = append(parts, fc.pathShape(a, use, depth+1))
			}
			if len(parts) == 0 {
				return "*"
			}
			return strings.Join(parts, "/")
		case "str":
			if len(args) == 1 {
				return fc.pathShape(args[0], use, depth+1)
			}
		}
		// "...{}".format(x) keeps its literal skeleton.
		if len(n.Children) > 0 && n.Children[0].Kind == ir.NodeKindAttribute {
			c := n.Children[0]
			if len(c.Children) >= 2 && c.Children[0].Kind == ir.NodeKindLiteral {
				if m := c.Children[len(c.Children)-1]; m.Kind == ir.NodeKindIdentifier && m.Text == "format" {
					return fstringField.ReplaceAllString(stringShape(c.Children[0].Text), "*")
				}
			}
		}
		return "*"
	case ir.NodeKindBinaryOp:
		var b strings.Builder
		for _, c := range n.Children {
			if c.Kind == ir.NodeKindUnknown && len(c.Children) == 0 {
				switch strings.TrimSpace(c.Text) {
				case "/":
					b.WriteString("/")
				}
				continue
			}
			b.WriteString(fc.pathShape(c, use, depth+1))
		}
		return b.String()
	}
	return "*"
}

// stringShape strips a Python string literal's prefix and quotes when the
// builder left them on (f-strings, raw and byte strings), replacing each
// f-string replacement field with "*".
func stringShape(text string) string {
	i := 0
	isF := false
	for i < len(text) && i < 3 && strings.ContainsRune("rRbBuUfF", rune(text[i])) {
		if text[i] == 'f' || text[i] == 'F' {
			isF = true
		}
		i++
	}
	body := text[i:]
	if len(body) < 2 || (body[0] != '"' && body[0] != '\'') {
		return text // already unquoted by the builder
	}
	q := body[:1]
	if strings.HasPrefix(body, strings.Repeat(q, 3)) && len(body) >= 6 {
		q = strings.Repeat(q, 3)
	}
	if strings.HasPrefix(body, q) && strings.HasSuffix(body, q) && len(body) >= 2*len(q) {
		body = body[len(q) : len(body)-len(q)]
	}
	if isF {
		body = fstringField.ReplaceAllString(body, "*")
	}
	return body
}

// skipsContext reports whether rule r opted out of context c.
func skipsContext(r *rules.Rule, c string) bool {
	for _, s := range r.SkipContexts {
		if s == c {
			return true
		}
	}
	return false
}

// angularImportRe and useClientRe recognise modules that only run in a
// browser: anything importing Angular's core runtime, and React modules that
// declare themselves client components.
var (
	angularImportRe = regexp.MustCompile(`(?m)^\s*import\s[^;]*from\s+['"]@angular/core['"]`)
	useClientRe     = regexp.MustCompile(`^(?:\s|//[^\n]*\n|/\*[\s\S]*?\*/)*['"]use client['"]`)
)

// IsBrowserContext reports whether a JavaScript/TypeScript file runs in a
// browser rather than on a server. It recognises three signals, any one of
// which is enough:
//
//   - the module imports @angular/core (Angular has no server-side runtime
//     for application services and components outside SSR, which still
//     executes them as browser code);
//   - the module starts with a "use client" directive (React/Next.js);
//   - the file sits under a directory named "frontend" (the conventional
//     root of a separately-built browser app in a monorepo, e.g.
//     frontend/src/app).
//
// Inline <script> blocks in HTML are browser code by construction; the SAST
// scanner marks those itself without calling this.
func IsBrowserContext(path string, source []byte) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.EqualFold(seg, "frontend") {
			return true
		}
	}
	return angularImportRe.Match(source) || useClientRe.Match(source)
}

// moduleConstants returns the names bound exactly once in the whole file, at
// module level, directly to a literal, mapped to the literal's value. A name
// assigned anywhere else (another module-level assignment, an augmented
// assignment, or any assignment inside a function) is left out: its value at
// the point of use is no longer known.
func moduleConstants(root *ir.IRNode) map[string]string {
	if root == nil {
		return nil
	}
	counts := map[string]int{}
	values := map[string]string{}
	ir.Walk(root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindAssignment {
			return true
		}
		lhs, _ := n.Attrs["lhs"].(string)
		if lhs == "" {
			return true
		}
		counts[lhs]++
		if aug, _ := n.Attrs["augmented"].(bool); aug {
			return true
		}
		if enclosingFunction(n) != nil || len(n.Children) == 0 {
			return true
		}
		if rhs := n.Children[len(n.Children)-1]; rhs.Kind == ir.NodeKindLiteral {
			values[lhs] = rhs.Text
		}
		return true
	})
	out := map[string]string{}
	for name, v := range values {
		if counts[name] == 1 {
			out[name] = v
		}
	}
	return out
}

// literalValue returns the constant string value of an argument node: a
// literal's own text, or a bare identifier that names a module constant. An
// identifier used as a member name (obj.ALGORITHM) is not resolved, since it
// refers to an attribute rather than the module-level binding.
func literalValue(a *ir.IRNode, consts map[string]string) (string, bool) {
	switch a.Kind {
	case ir.NodeKindLiteral:
		return a.Text, true
	case ir.NodeKindIdentifier:
		if a.Parent != nil && a.Parent.Kind == ir.NodeKindAttribute {
			return "", false
		}
		v, ok := consts[a.Text]
		return v, ok
	}
	return "", false
}

// broadExceptionTypes are catch-all exception classes. Catching one of these
// and doing nothing hides every failure; catching anything narrower is a
// decision about one specific failure.
var broadExceptionTypes = map[string]bool{
	"Exception": true, "BaseException": true, "Throwable": true,
	"Error": true, "RuntimeException": true, "object": true,
}

// isBroadHandler reports whether a clause catches everything: a bare except,
// an untyped catch (every JS/TS catch), or a type list naming a catch-all.
func isBroadHandler(h ir.ExceptHandler) bool {
	if h.IsBare || len(h.Types) == 0 {
		return true
	}
	for _, t := range h.Types {
		for _, name := range exceptionTypeNames(t) {
			if broadExceptionTypes[name] {
				return true
			}
		}
	}
	return false
}

// exceptionTypeNames splits one recorded except-type expression into its
// class names: "(KeyError, ValueError)" -> [KeyError ValueError],
// "Exception as e" -> [Exception], "builtins.Exception" -> [Exception].
func exceptionTypeNames(expr string) []string {
	if i := strings.Index(expr, " as "); i >= 0 {
		expr = expr[:i]
	}
	expr = strings.Trim(strings.TrimSpace(expr), "()")
	var out []string
	for _, part := range strings.FieldsFunc(expr, func(r rune) bool { return r == ',' || r == '|' }) {
		part = strings.TrimSpace(part)
		if i := strings.LastIndexByte(part, '.'); i >= 0 {
			part = part[i+1:]
		}
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// exceptHandlerMatches applies every set constraint of p to one clause.
func exceptHandlerMatches(p rules.ExceptHandlerPattern, h ir.ExceptHandler) bool {
	if p.Bare != nil && h.IsBare != *p.Bare {
		return false
	}
	if p.Empty != nil && h.IsEmptyBody != *p.Empty {
		return false
	}
	if p.Broad != nil && isBroadHandler(h) != *p.Broad {
		return false
	}
	if p.Commented != nil && h.HasComment != *p.Commented {
		return false
	}
	return true
}

// tryBodyCallsOnly reports whether a try node's protected block makes at
// least one call and every call's callee matches pattern.
func tryBodyCallsOnly(n *ir.IRNode, pattern string) bool {
	if n.Kind != ir.NodeKindTry {
		return false
	}
	re := cachedRegexp(pattern)
	if re == nil {
		return false
	}
	var body *ir.IRNode
	for _, c := range n.Children {
		if c.Kind == ir.NodeKindBlock {
			body = c
			break
		}
	}
	if body == nil {
		return false
	}
	calls := 0
	for _, d := range ir.Descendants(body) {
		if d.Kind != ir.NodeKindCall {
			continue
		}
		calls++
		if !re.MatchString(calleeText(d)) {
			return false
		}
	}
	return calls > 0
}

// scopeContains reports whether any node in n's innermost enclosing function
// (or the whole file, for module-level code) satisfies pred.
func scopeContains(n *ir.IRNode, pred func(*ir.IRNode) bool) bool {
	scope := enclosingFunction(n)
	if scope == nil {
		scope = n
		for scope.Parent != nil {
			scope = scope.Parent
		}
	}
	for _, d := range ir.Descendants(scope) {
		if pred(d) {
			return true
		}
	}
	return false
}

// functionName returns a named function's own name, or "" for an anonymous
// function or arrow function. An arrow function's single bare parameter is
// also an Identifier child, so arrows (recognised by their "=>" token) are
// treated as anonymous outright.
func functionName(f *ir.IRNode) string {
	for _, c := range f.Children {
		if strings.TrimSpace(c.Text) == "=>" {
			return ""
		}
	}
	for _, c := range f.Children {
		if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
			return c.Text
		}
	}
	return ""
}

// contextNames returns the name(s) an expression's value is bound to: the
// target of the assignment it is the right-hand side of, the key of the
// object property it is the value of, or -- for a returned value, including
// an arrow function's expression body -- the enclosing function's name (or,
// for an anonymous function, the name that function is itself bound to).
//
// The climb stops at the first statement boundary, so a value used as a call
// argument inside an expression statement, a loop bound or a condition has
// no binding name at all.
func contextNames(n *ir.IRNode) []string {
	cur := n
	for p := n.Parent; p != nil; cur, p = p, p.Parent {
		switch p.Kind {
		case ir.NodeKindAssignment:
			if len(p.Children) > 0 && p.Children[0] == cur {
				return nil // n is the assignment target itself
			}
			lhs, _ := p.Attrs["lhs"].(string)
			return []string{lhs}
		case ir.NodeKindKeywordArg:
			name, _ := p.Attrs["kwarg_name"].(string)
			return []string{name}
		case ir.NodeKindReturn:
			f := enclosingFunction(p)
			if f == nil {
				return nil
			}
			if name := functionName(f); name != "" {
				return []string{name}
			}
			cur, p = f, f // continue the climb from the anonymous function
		case ir.NodeKindFunction:
			// Reached directly (not through a Return): an arrow function's
			// expression body, which is an implicit return.
			if name := functionName(p); name != "" {
				return []string{name}
			}
		case ir.NodeKindBlock, ir.NodeKindModule, ir.NodeKindIf, ir.NodeKindFor,
			ir.NodeKindWhile, ir.NodeKindTry, ir.NodeKindClass, ir.NodeKindSwitch:
			return nil
		}
	}
	return nil
}

// snakeCase normalises an identifier or member-expression text to lower
// snake_case words: "issueConfirmationCode" -> "issue_confirmation_code",
// "SECRET_KEY" -> "secret_key", "this.resetToken" -> "this_reset_token",
// "sessionID" -> "session_id". Filters anchor on word boundaries against it.
func snakeCase(s string) string {
	var b strings.Builder
	rs := []rune(s)
	prevUnderscore := true
	for i, r := range rs {
		switch {
		case unicode.IsUpper(r):
			// Start a new word at a lower->Upper transition, and at the last
			// capital of an acronym followed by a lowercase letter (IDToken).
			if !prevUnderscore && i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
				(i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			prevUnderscore = false
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevUnderscore = false
		default:
			if !prevUnderscore {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}
