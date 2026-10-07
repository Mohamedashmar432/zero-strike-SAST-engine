package engine

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

// regexCache memoises compiled filter regexes. Rules are shared by every file
// and goroutine in a scan, so compiling on each evaluation would put a
// regexp.Compile on the per-node hot path.
var regexCache sync.Map // string -> *regexp.Regexp (nil on compile error)

func compiled(pattern string) *regexp.Regexp {
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
	re := compiled(pattern)
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

// enclosingFunction returns the innermost function node containing n, or nil
// for module-level code.
func enclosingFunction(n *ir.IRNode) *ir.IRNode {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Kind == ir.NodeKindFunction {
			return p
		}
	}
	return nil
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
