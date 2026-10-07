//go:build cgo

package typescript

import (
	"regexp"

	sitter "github.com/smacker/go-tree-sitter"
)

// The error-binding helpers below are duplicated verbatim in
// internal/parser/javascript/errbinding.go: the two grammars share these node
// shapes, but the builders live in separate packages (see the TS builder's
// doc comment), so keep the two copies in step.

// errParamName is the naming convention for the error parameter of a Node
// err-first callback: fs.readFile(p, (err, data) => ...), exec(cmd, function
// (error, stdout) {...}), file.mv(dest, function (err) {...}). The name is
// only consulted for a function that sits in the LAST argument slot of a
// call; position is what makes it a callback, the name is what makes the
// first parameter the error rather than a value.
var errParamName = regexp.MustCompile(`^(?:e|er|err|error|ex|exc|exception|[A-Za-z_$][\w$]*(?:Err|Error))$`)

// valueCallbackMethods take callbacks whose first parameter is an element or a
// resolved value, never an error, whatever it happens to be called.
// arr.forEach((e, i) => ...) is the case that matters: `e` is the most common
// name for both an element and a caught error.
var valueCallbackMethods = map[string]bool{
	"forEach": true, "map": true, "filter": true, "reduce": true, "reduceRight": true,
	"some": true, "every": true, "find": true, "findIndex": true, "findLast": true,
	"findLastIndex": true, "flatMap": true, "sort": true, "subscribe": true,
}

// catchBinding returns the identifier bound by a catch clause (`catch (err)`),
// or "" for a binding-less `catch {}` or a destructuring pattern.
func catchBinding(clause *sitter.Node, source []byte) string {
	p := clause.ChildByFieldName("parameter")
	if p == nil || p.Type() != "identifier" {
		return ""
	}
	return p.Content(source)
}

// errorCallbackParam returns the name of fn's first parameter when fn is a
// callback whose first parameter receives an error:
//
//   - p.catch(cb)            -> cb's first parameter, whatever its name
//   - p.then(ok, cb)         -> cb's first parameter, whatever its name
//   - emitter.on('error', cb) -> cb's first parameter, whatever its name
//   - f(..., cb)             -> cb's first parameter when cb is the last
//     argument and the parameter is named like an error (err, error, e, ...),
//     except for the value-callback methods above
//
// It returns "" for anything else, including a function that is not passed
// as a call argument at all.
func errorCallbackParam(fn *sitter.Node, source []byte) string {
	first := firstParamName(fn, source)
	if first == "" {
		return ""
	}
	args := fn.Parent()
	if args == nil || args.Type() != "arguments" {
		return ""
	}
	call := args.Parent()
	if call == nil || call.Type() != "call_expression" {
		return ""
	}
	pos, count := -1, 0
	var arg0 *sitter.Node
	for i := 0; i < int(args.NamedChildCount()); i++ {
		c := args.NamedChild(i)
		if c.Type() == "comment" {
			continue
		}
		if count == 0 {
			arg0 = c
		}
		if c.StartByte() == fn.StartByte() && c.EndByte() == fn.EndByte() {
			pos = count
		}
		count++
	}
	if pos < 0 {
		return ""
	}
	method := ""
	if callee := call.ChildByFieldName("function"); callee != nil && callee.Type() == "member_expression" {
		if prop := callee.ChildByFieldName("property"); prop != nil {
			method = prop.Content(source)
		}
	}
	switch method {
	case "catch":
		if pos == 0 {
			return first
		}
		return ""
	case "then":
		if pos == 1 {
			return first
		}
		return ""
	case "on", "once", "addListener", "prependListener":
		if pos == 1 && arg0 != nil && arg0.Type() == "string" && unquoteLiteral(arg0.Content(source)) == "error" {
			return first
		}
		return ""
	}
	if valueCallbackMethods[method] {
		return ""
	}
	if pos == count-1 && errParamName.MatchString(first) {
		return first
	}
	return ""
}

// firstParamName returns the name of a function's first declared parameter
// when that parameter is a plain identifier (optionally defaulted or, in
// TypeScript, type-annotated), and "" otherwise.
func firstParamName(fn *sitter.Node, source []byte) string {
	if p := fn.ChildByFieldName("parameter"); p != nil {
		if p.Type() == "identifier" {
			return p.Content(source)
		}
		return ""
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return ""
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		p := params.NamedChild(i)
		switch p.Type() {
		case "comment":
			continue
		case "identifier":
			return p.Content(source)
		case "assignment_pattern":
			if left := p.ChildByFieldName("left"); left != nil && left.Type() == "identifier" {
				return left.Content(source)
			}
		case "required_parameter", "optional_parameter":
			if pat := p.ChildByFieldName("pattern"); pat != nil && pat.Type() == "identifier" {
				return pat.Content(source)
			}
		}
		return ""
	}
	return ""
}
