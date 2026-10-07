package engine

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

// isJSLike reports whether lang uses the JavaScript-family IR (the JS and TS
// builders lower the same grammar shapes).
func isJSLike(lang core.Language) bool {
	return lang == core.LangJavaScript || lang == core.LangTypeScript
}

// fileCtx carries per-file state shared by every rule evaluated against one
// file: the taint sets, and for JS/TS the module bindings and object-literal
// initializers that some filters resolve through. Built once per Match call,
// never shared across files or goroutines.
type fileCtx struct {
	lang    core.Language
	tainted map[string]bool
	weak    map[string]bool
	root    *ir.IRNode

	jsOnce   bool
	bindings map[string]string        // local name -> canonical module path
	objDecls map[string][]*ir.IRNode // local name -> object-literal initializers

	lastNode *ir.IRNode
	lastText string
}

func newFileCtx(f *ir.IRFile, tainted, weak map[string]bool) *fileCtx {
	return &fileCtx{lang: f.Language, tainted: tainted, weak: weak, root: f.Root}
}

// callee returns calleeTextFor(n), memoized for the node the walk is on (the
// index lookup and every callee filter on that node ask for it).
func (fc *fileCtx) callee(n *ir.IRNode) string {
	if fc.lastNode != n {
		fc.lastNode, fc.lastText = n, calleeTextFor(n, fc.lang)
	}
	return fc.lastText
}

var regexCache sync.Map // pattern -> *regexp.Regexp (nil when invalid)

// cachedRegexp compiles pattern once per process. Rule regexes are validated
// at load time (see rules.Validator); an invalid one simply never matches.
func cachedRegexp(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	regexCache.Store(pattern, re)
	return re
}

func regexMatches(pattern, s string) bool {
	re := cachedRegexp(pattern)
	return re != nil && re.MatchString(s)
}

// ---------------------------------------------------------------------------
// Callee rendering (IMP-04)
// ---------------------------------------------------------------------------

// jsCalleeText renders a JS/TS call node's callee.
//
// The historical calleeText kept only Identifier and Attribute children, so
// any receiver that was not a plain name vanished from the text:
//
//	this.http.get(u)          -> "http.get"   (Angular HttpClient, matched Node's http.get SSRF rule)
//	new RegExp(p).exec(s)     -> "exec"       (matched child_process exec)
//	res.status(500).send(e)   -> "send"       (could not be matched deliberately)
//
// Here every receiver keeps a segment: `this`, a call result as `<callee>()`,
// a constructor result as `new <ctor>()`, a subscript as `<object>[]`, and any
// other expression as `<expr>`. So the three calls above render as
// this.http.get, new RegExp().exec and res.status().send. Exact callee rules
// stop matching unrelated chains, and a chained terminal method is matched on
// purpose, either exactly (res.status().send), by dot-boundary suffix
// (callee_suffix: send), or by callee_pattern.
//
// A `new` expression's own callee is still just the constructor (new RegExp(x)
// -> "RegExp"), as before. resolve, when non-nil, may substitute the root
// identifier's text (see canonicalCallee).
func jsCalleeText(n *ir.IRNode, resolve func(*ir.IRNode) (string, bool)) string {
	fn := jsCalleeNode(n)
	if fn == nil {
		return ""
	}
	return jsExprText(fn, resolve)
}

// jsCalleeNode returns the function-position child of a call or new
// expression: Children[0] for a call, the node after the `new` keyword for a
// constructor call.
func jsCalleeNode(n *ir.IRNode) *ir.IRNode {
	if n == nil || n.Kind != ir.NodeKindCall || len(n.Children) == 0 {
		return nil
	}
	if isNewExpression(n) {
		if len(n.Children) < 2 {
			return nil
		}
		return n.Children[1]
	}
	return n.Children[0]
}

func isNewExpression(n *ir.IRNode) bool {
	return n.Kind == ir.NodeKindCall && len(n.Children) > 0 &&
		n.Children[0].Kind == ir.NodeKindUnknown && n.Children[0].Text == "new"
}

func isLeaf(n *ir.IRNode) bool { return len(n.Children) == 0 }

// jsExprText renders an expression node as dotted text in the jsCalleeText
// scheme. It is also what ArgumentMatchesAt matches against: a literal
// renders as its unquoted value, a + concatenation as its operands joined by
// "+".
func jsExprText(n *ir.IRNode, resolve func(*ir.IRNode) (string, bool)) string {
	if n == nil {
		return ""
	}
	switch n.Kind {
	case ir.NodeKindIdentifier:
		if resolve != nil {
			if s, ok := resolve(n); ok {
				return s
			}
		}
		return n.Text
	case ir.NodeKindLiteral:
		return n.Text
	case ir.NodeKindAttribute:
		if len(n.Children) == 0 {
			return "<expr>"
		}
		obj := jsExprText(n.Children[0], resolve)
		for _, c := range n.Children[1:] {
			if c.Kind == ir.NodeKindUnknown && c.Text == "[" {
				return obj + "[]"
			}
		}
		prop := n.Children[len(n.Children)-1]
		if prop.Kind != ir.NodeKindIdentifier {
			return obj + ".<expr>"
		}
		return obj + "." + prop.Text
	case ir.NodeKindCall:
		if isNewExpression(n) {
			return "new " + jsCalleeText(n, nil) + "()"
		}
		if resolve != nil {
			if m := requireModule(n); m != "" {
				return m
			}
		}
		fn := jsCalleeNode(n)
		if fn == nil {
			return "<expr>()"
		}
		return jsExprText(fn, resolve) + "()"
	case ir.NodeKindBinaryOp:
		var parts []string
		for _, c := range n.Children {
			if c.Kind == ir.NodeKindUnknown && isLeaf(c) {
				continue // operator token
			}
			parts = append(parts, jsExprText(c, resolve))
		}
		return strings.Join(parts, "+")
	case ir.NodeKindUnknown:
		if isLeaf(n) {
			switch n.Text {
			case "this", "super":
				return n.Text
			}
			return "<expr>"
		}
		// TypeScript non-null assertion `x!` renders as x.
		if len(n.Children) == 2 && n.Children[1].Text == "!" {
			return jsExprText(n.Children[0], resolve)
		}
		return "<expr>"
	}
	return "<expr>"
}

// exprText renders an argument for ArgumentMatchesAt in lang's scheme.
func exprText(n *ir.IRNode, lang core.Language) string {
	if isJSLike(lang) {
		return jsExprText(n, nil)
	}
	switch n.Kind {
	case ir.NodeKindAttribute:
		return attributeText(n)
	case ir.NodeKindCall:
		return calleeText(n) + "()"
	}
	return n.Text
}

// ---------------------------------------------------------------------------
// Module bindings (canonical callee)
// ---------------------------------------------------------------------------

// normalizeModule turns a module specifier into the dotted prefix used by
// canonical callees: node:child_process -> child_process, fs/promises ->
// fs.promises, next/navigation -> next.navigation. Relative and absolute
// specifiers (./models, /x) name first-party files, not packages, and return "".
func normalizeModule(spec string) string {
	spec = strings.TrimPrefix(spec, "node:")
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	return strings.ReplaceAll(spec, "/", ".")
}

// requireModule returns the normalized module of a `require('<lit>')` call,
// or "".
func requireModule(n *ir.IRNode) string {
	if n.Kind != ir.NodeKindCall || isNewExpression(n) || len(n.Children) == 0 {
		return ""
	}
	if fn := n.Children[0]; fn.Kind != ir.NodeKindIdentifier || fn.Text != "require" {
		return ""
	}
	args := argumentNodes(n)
	if len(args) == 0 || args[0].Kind != ir.NodeKindLiteral {
		return ""
	}
	return normalizeModule(args[0].Text)
}

// ensureJS builds the JS/TS binding and object-initializer tables once.
func (fc *fileCtx) ensureJS() {
	if fc.jsOnce {
		return
	}
	fc.jsOnce = true
	fc.bindings = make(map[string]string)
	fc.objDecls = make(map[string][]*ir.IRNode)
	if fc.root == nil || !isJSLike(fc.lang) {
		return
	}
	ir.Walk(fc.root, func(n *ir.IRNode) bool {
		switch n.Kind {
		case ir.NodeKindImport:
			fc.bindImport(n)
		case ir.NodeKindAssignment:
			if len(n.Children) < 2 {
				return true
			}
			left, right := n.Children[0], n.Children[len(n.Children)-1]
			if left.Kind == ir.NodeKindIdentifier && isObjectLiteral(right) {
				fc.objDecls[left.Text] = append(fc.objDecls[left.Text], right)
			}
			if m := fc.modulePath(right); m != "" {
				fc.bindPattern(left, m)
			}
		}
		return true
	})
}

// modulePath resolves an initializer to the module path it denotes:
// require('m') -> m, require('m').x -> m.x, promisify(<that>) -> <that>, and
// an identifier already bound to a module -> its binding.
func (fc *fileCtx) modulePath(n *ir.IRNode) string {
	switch n.Kind {
	case ir.NodeKindCall:
		if m := requireModule(n); m != "" {
			return m
		}
		if isNewExpression(n) {
			return ""
		}
		if t := jsCalleeText(n, nil); t == "promisify" || strings.HasSuffix(t, ".promisify") {
			if args := argumentNodes(n); len(args) > 0 {
				return fc.modulePath(args[0])
			}
		}
	case ir.NodeKindAttribute:
		if len(n.Children) == 0 {
			return ""
		}
		prop := n.Children[len(n.Children)-1]
		if prop.Kind != ir.NodeKindIdentifier {
			return ""
		}
		for _, c := range n.Children {
			if c.Text == "[" {
				return ""
			}
		}
		if base := fc.modulePath(n.Children[0]); base != "" {
			return base + "." + prop.Text
		}
	case ir.NodeKindIdentifier:
		return fc.bindings[n.Text]
	}
	return ""
}

// bindPattern binds a declarator's left side to module path m: a plain name,
// or each name of an object destructuring pattern ({ exec, spawn: run }).
func (fc *fileCtx) bindPattern(left *ir.IRNode, m string) {
	if left.Kind == ir.NodeKindIdentifier {
		fc.bindings[left.Text] = m
		return
	}
	if left.Kind != ir.NodeKindUnknown || len(left.Children) == 0 || left.Children[0].Text != "{" {
		return
	}
	for _, c := range left.Children {
		switch {
		case c.Kind == ir.NodeKindUnknown && isLeaf(c) && isJSIdent(c.Text):
			// shorthand_property_identifier_pattern
			fc.bindings[c.Text] = m + "." + c.Text
		case c.Kind == ir.NodeKindUnknown && len(c.Children) >= 3:
			// pair_pattern: key ':' value
			key, val := c.Children[0], c.Children[len(c.Children)-1]
			if key.Kind == ir.NodeKindIdentifier && val.Kind == ir.NodeKindIdentifier {
				fc.bindings[val.Text] = m + "." + key.Text
			}
		}
	}
}

// bindImport records the bindings of an ES import declaration:
// default (import fs from 'fs'), namespace (import * as cp from
// 'child_process') and named (import { exec, promises as fsp } from ...).
func (fc *fileCtx) bindImport(n *ir.IRNode) {
	m := ""
	for _, c := range n.Children {
		if c.Kind == ir.NodeKindLiteral {
			m = normalizeModule(c.Text)
		}
	}
	if m == "" {
		return
	}
	for _, clause := range n.Children {
		if clause.Kind != ir.NodeKindUnknown || isLeaf(clause) {
			continue
		}
		for _, c := range clause.Children {
			switch {
			case c.Kind == ir.NodeKindIdentifier:
				fc.bindings[c.Text] = m
			case c.Kind == ir.NodeKindUnknown && len(c.Children) > 0 && c.Children[0].Text == "*":
				if id := lastIdentifier(c); id != "" {
					fc.bindings[id] = m
				}
			case c.Kind == ir.NodeKindUnknown && len(c.Children) > 0 && c.Children[0].Text == "{":
				for _, spec := range c.Children {
					if spec.Kind == ir.NodeKindIdentifier {
						fc.bindings[spec.Text] = m + "." + spec.Text
						continue
					}
					var ids []string
					for _, x := range spec.Children {
						if x.Kind == ir.NodeKindIdentifier {
							ids = append(ids, x.Text)
						}
					}
					if len(ids) > 0 {
						fc.bindings[ids[len(ids)-1]] = m + "." + ids[0]
					}
				}
			}
		}
	}
}

func lastIdentifier(n *ir.IRNode) string {
	for i := len(n.Children) - 1; i >= 0; i-- {
		if n.Children[i].Kind == ir.NodeKindIdentifier {
			return n.Children[i].Text
		}
	}
	return ""
}

var jsIdentRe = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

func isJSIdent(s string) bool { return jsIdentRe.MatchString(s) }

func isObjectLiteral(n *ir.IRNode) bool {
	return n.Kind == ir.NodeKindUnknown && len(n.Children) > 0 && n.Children[0].Text == "{"
}

// calleeRoot returns the leftmost node of a callee's member chain.
func calleeRoot(n *ir.IRNode) *ir.IRNode {
	for n != nil && n.Kind == ir.NodeKindAttribute && len(n.Children) > 0 {
		n = n.Children[0]
	}
	return n
}

// canonicalCallee renders a call's callee with its root replaced by the
// module it is bound to, and reports whether the root was bound at all. The
// raw rendering is returned (bound=false) when no binding applies.
func (fc *fileCtx) canonicalCallee(n *ir.IRNode) (string, bool) {
	fc.ensureJS()
	fn := jsCalleeNode(n)
	if fn == nil {
		return "", false
	}
	root := calleeRoot(fn)
	bound := false
	if root != nil {
		switch root.Kind {
		case ir.NodeKindIdentifier:
			_, bound = fc.bindings[root.Text]
		case ir.NodeKindCall:
			bound = requireModule(root) != ""
		}
	}
	text := jsExprText(fn, func(id *ir.IRNode) (string, bool) {
		if id != root {
			return "", false
		}
		m, ok := fc.bindings[id.Text]
		return m, ok
	})
	return text, bound
}

// resolvedObjects returns the object-literal initializer(s) an identifier
// argument most plausibly refers to at call site n: the nearest preceding
// declaration inside the same function if there is one, else the nearest
// preceding one in the file, else the first.
func (fc *fileCtx) resolvedObjects(name string, n *ir.IRNode) []*ir.IRNode {
	fc.ensureJS()
	decls := fc.objDecls[name]
	if len(decls) <= 1 {
		return decls
	}
	fn := enclosingFunction(n)
	var sameFn, before *ir.IRNode
	for _, d := range decls {
		if d.Location.StartLine > n.Location.StartLine {
			continue
		}
		before = d
		if enclosingFunction(d) == fn {
			sameFn = d
		}
	}
	switch {
	case sameFn != nil:
		return []*ir.IRNode{sameFn}
	case before != nil:
		return []*ir.IRNode{before}
	}
	return decls[:1]
}

func enclosingFunction(n *ir.IRNode) *ir.IRNode {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Kind == ir.NodeKindFunction {
			return p
		}
	}
	return nil
}

// anyResolvedObjectArgument applies pred to the pairs of the object literal
// each identifier argument of n was initialized with (JS/TS only).
func (fc *fileCtx) anyResolvedObjectArgument(n *ir.IRNode, pred func(*ir.IRNode) bool) bool {
	if !isJSLike(fc.lang) {
		return false
	}
	for _, a := range argumentNodes(n) {
		if a.Kind != ir.NodeKindIdentifier {
			continue
		}
		for _, obj := range fc.resolvedObjects(a.Text, n) {
			for _, d := range ir.Descendants(obj) {
				if pred(d) {
					return true
				}
			}
		}
	}
	return false
}

// kwargValueTainted implements KwargPattern.ValueTainted for a pair node.
func (fc *fileCtx) kwargValueTainted(pair *ir.IRNode) bool {
	if len(pair.Children) == 0 {
		return false
	}
	v := pair.Children[len(pair.Children)-1]
	switch {
	case v.Kind == ir.NodeKindIdentifier, v.Kind == ir.NodeKindAttribute, v.Kind == ir.NodeKindCall:
		return fc.subtreeTainted(v)
	case isObjectLiteral(v):
		for _, c := range v.Children {
			// spread_element: '...' expr
			if c.Kind == ir.NodeKindUnknown && len(c.Children) >= 2 && c.Children[0].Text == "..." {
				if fc.subtreeTainted(c.Children[len(c.Children)-1]) {
					return true
				}
			}
		}
	}
	return false
}

func (fc *fileCtx) subtreeTainted(n *ir.IRNode) bool {
	check := func(x *ir.IRNode) bool {
		if x.Kind == ir.NodeKindIdentifier && fc.tainted[x.Text] {
			if p, _ := x.Attrs["prop"].(bool); !p {
				return true
			}
		}
		return isDirectSourceExpression(x, fc.lang)
	}
	if check(n) {
		return true
	}
	for _, d := range ir.Descendants(n) {
		if check(d) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Filters added for the JS/TS rule set
// ---------------------------------------------------------------------------

// evalJSFilters evaluates the callee/argument filters introduced alongside
// the JS/TS callee rendering. Each is inactive when unset.
func (fc *fileCtx) evalJSFilters(f rules.Filter, n *ir.IRNode) bool {
	if f.CalleePattern != "" {
		if n.Kind != ir.NodeKindCall || !regexMatches(f.CalleePattern, fc.callee(n)) {
			return false
		}
	}
	if f.CalleeCanonical != "" || f.CalleeResolved {
		if n.Kind != ir.NodeKindCall {
			return false
		}
		text, bound := fc.callee(n), false
		if isJSLike(fc.lang) {
			text, bound = fc.canonicalCallee(n)
		}
		if f.CalleeResolved && !bound {
			return false
		}
		if f.CalleeCanonical != "" && !regexMatches(f.CalleeCanonical, text) {
			return false
		}
	}
	if f.ArgumentMatchesAt != nil {
		args := argumentNodes(n)
		i := f.ArgumentMatchesAt.Index
		if i < 0 {
			i += len(args)
		}
		if i < 0 || i >= len(args) || !regexMatches(f.ArgumentMatchesAt.Pattern, exprText(args[i], fc.lang)) {
			return false
		}
	}
	if f.DynamicStringArgumentIndex != nil {
		args := argumentNodes(n)
		i := *f.DynamicStringArgumentIndex
		if i < 0 {
			i += len(args)
		}
		if i < 0 || i >= len(args) || !isDynamicString(args[i]) {
			return false
		}
	}
	if f.ArgumentReferencesErrorBinding {
		if !isJSLike(fc.lang) || !argumentReferencesErrorBinding(n) {
			return false
		}
	}
	return true
}

// isDynamicString reports whether a is a string assembled at runtime: a
// template literal containing a ${} substitution, or a + concatenation.
func isDynamicString(a *ir.IRNode) bool {
	switch a.Kind {
	case ir.NodeKindLiteral:
		return strings.Contains(a.Text, "${")
	case ir.NodeKindBinaryOp:
		for _, c := range a.Children {
			if c.Kind == ir.NodeKindUnknown && c.Text == "+" {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Error bindings (IMP-06, CWE-209)
// ---------------------------------------------------------------------------

// benignErrorFields are error properties that carry a classification, not
// the error's text or internals: sending err.code or err.status discloses
// nothing a client did not already cause.
var benignErrorFields = map[string]bool{
	"code": true, "name": true, "status": true, "statusCode": true, "errno": true,
	"type": true, "kind": true, "length": true, "isAxiosError": true, "expose": true,
}

type errBinding struct {
	name  string
	scope *ir.IRNode // catch clause or callback function that binds name
}

// errorBindingsAt returns the error bindings visible at n, innermost first.
// A name re-declared as an ordinary parameter of a nearer function shadows
// an outer binding of the same name.
func errorBindingsAt(n *ir.IRNode) []errBinding {
	shadow := map[string]bool{}
	var out []errBinding
	for p := n.Parent; p != nil; p = p.Parent {
		if eb, _ := p.Attrs["error_binding"].(string); eb != "" && !shadow[eb] {
			out = append(out, errBinding{eb, p})
			shadow[eb] = true
		}
		if p.Kind != ir.NodeKindFunction {
			continue
		}
		if ep, _ := p.Attrs["error_param"].(string); ep != "" && !shadow[ep] {
			out = append(out, errBinding{ep, p})
		}
		params, _ := p.Attrs["parameters"].([]string)
		for _, prm := range params {
			shadow[prm] = true
		}
	}
	return out
}

// argumentReferencesErrorBinding implements the filter of the same name.
//
// Besides the bindings visible at n, it follows one level of same-function
// propagation: a variable assigned (before n) from an expression that
// references an error binding carries it too. That covers
// `const msg = err.message; res.send(msg)` and dvws-node's
// `catch (err) { result.error = err } ... res.send(result)`, where the send
// sits after the catch block rather than inside it.
func argumentReferencesErrorBinding(n *ir.IRNode) bool {
	names := map[string]bool{}
	bindings := errorBindingsAt(n)
	for _, b := range bindings {
		names[b.name] = true
	}
	// Catch clauses elsewhere in the same function can still feed a variable
	// that is sent after the try statement.
	fn := enclosingFunction(n)
	region := fn
	if region == nil {
		for region = n; region.Parent != nil; region = region.Parent {
		}
	}
	scopes := make([]errBinding, 0, len(bindings)+2)
	scopes = append(scopes, bindings...)
	for _, d := range ir.Descendants(region) {
		if eb, _ := d.Attrs["error_binding"].(string); eb != "" && enclosingFunction(d) == fn {
			scopes = append(scopes, errBinding{eb, d})
		}
	}
	derived := map[string]bool{}
	for _, b := range scopes {
		only := map[string]bool{b.name: true}
		for _, d := range ir.Descendants(b.scope) {
			if d.Kind != ir.NodeKindAssignment || d.Location.StartLine > n.Location.StartLine || len(d.Children) < 2 {
				continue
			}
			lhs, _ := d.Attrs["lhs"].(string)
			root := jsIdentPrefix.FindString(lhs)
			if root == "" || root == b.name {
				continue
			}
			rhs := d.Children[len(d.Children)-1]
			if referencesError(rhs, only, rhs) {
				derived[root] = true
			}
		}
	}
	for k := range derived {
		names[k] = true
	}
	if len(names) == 0 {
		return false
	}
	for _, a := range argumentNodes(n) {
		if referencesError(a, names, a) {
			return true
		}
	}
	return false
}

var jsIdentPrefix = regexp.MustCompile(`^[A-Za-z_$][\w$]*`)

// referencesError reports whether the subtree under top contains a
// reference to one of names that exposes the error's content.
func referencesError(top *ir.IRNode, names map[string]bool, root *ir.IRNode) bool {
	if isErrorRef(top, names, root) {
		return true
	}
	for _, d := range ir.Descendants(top) {
		if isErrorRef(d, names, root) {
			return true
		}
	}
	return false
}

func isErrorRef(id *ir.IRNode, names map[string]bool, top *ir.IRNode) bool {
	if id.Kind != ir.NodeKindIdentifier || !names[id.Text] {
		return false
	}
	if p, _ := id.Attrs["prop"].(bool); p {
		return false // {error: x} key or x.error property, not a reference
	}
	// A function between the reference and the argument root that declares
	// the same name as a parameter shadows the binding: items.map(e => e.id).
	for p := id.Parent; p != nil && p != top.Parent; p = p.Parent {
		if p.Kind == ir.NodeKindFunction {
			params, _ := p.Attrs["parameters"].([]string)
			for _, prm := range params {
				if prm == id.Text {
					return false
				}
			}
		}
	}
	// Climb the member chain: err.code / err.response.status are
	// classifications, not error text.
	e := id
	for e.Parent != nil && e.Parent.Kind == ir.NodeKindAttribute && len(e.Parent.Children) > 0 && e.Parent.Children[0] == e {
		last := e.Parent.Children[len(e.Parent.Children)-1]
		if last.Kind == ir.NodeKindIdentifier && benignErrorFields[last.Text] {
			return false
		}
		e = e.Parent
	}
	if e.Parent != nil && e.Parent.Kind == ir.NodeKindCall && len(e.Parent.Children) > 0 && e.Parent.Children[0] == e {
		e = e.Parent // err.toString()
	}
	p := e.Parent
	if p == nil {
		return true
	}
	switch p.Kind {
	case ir.NodeKindBinaryOp:
		for _, c := range p.Children {
			if c.Kind == ir.NodeKindUnknown && isLeaf(c) {
				switch c.Text {
				case "===", "!==", "==", "!=", "instanceof", "in", "<", ">", "<=", ">=":
					return false
				}
			}
		}
	case ir.NodeKindUnknown:
		if len(p.Children) > 0 && isLeaf(p.Children[0]) {
			switch p.Children[0].Text {
			case "!", "typeof", "void", "delete":
				return false
			}
		}
		// ternary condition: cond '?' a ':' b
		if len(p.Children) >= 5 && p.Children[0] == e && p.Children[1].Text == "?" {
			return false
		}
	}
	return true
}
