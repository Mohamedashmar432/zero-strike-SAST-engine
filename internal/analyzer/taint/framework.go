package taint

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/fwdetect"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// fwEntry is one detected framework's entry-point lookup for the file.
type fwEntry struct {
	name    string
	entries *fwdetect.Entries
}

// fwSeeding is the framework-aware replacement for blanket parameter seeding,
// built only for a file with high-confidence framework evidence.
type fwSeeding struct {
	entries []fwEntry
	sources []*regexp.Regexp
}

// frameworkSeeding returns the seeding plan for file, or nil when the file has
// no high-confidence framework (or only ones with no profile), in which case
// BuildContext keeps seeding every parameter.
func frameworkSeeding(file *ir.IRFile) *fwSeeding {
	var fw *fwSeeding
	for _, hit := range file.Frameworks {
		p := fwdetect.ProfileFor(hit.Name)
		if p == nil {
			continue
		}
		if fw == nil {
			fw = &fwSeeding{}
		}
		fw.entries = append(fw.entries, fwEntry{name: p.Name, entries: p.Index(file.Root)})
		fw.sources = append(fw.sources, p.SourcesFor(hit.Evidence)...)
	}
	return fw
}

// seedCalledHelpers taints the parameters of every same-file function that some
// call passes a tainted argument (a tainted name, or an inline source), and
// reports whether it tainted anything new. Callee and callee-name matching use
// the builders' Attrs["callee_src"]; the arguments are the call's last child,
// which is the argument container in every grammar that records callee_src.
func seedCalledHelpers(file *ir.IRFile, pats languagePatterns, tainted map[string]bool, reasons map[string]string, weak map[string]bool) bool {
	byName := map[string][]*ir.IRNode{}
	ir.Walk(file.Root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindFunction {
			return true
		}
		if params, _ := n.Attrs["parameters"].([]string); len(params) == 0 {
			return true
		}
		if name := helperName(n); name != "" {
			byName[name] = append(byName[name], n)
		}
		return true
	})
	if len(byName) == 0 {
		return false
	}
	changed := false
	ir.Walk(file.Root, func(call *ir.IRNode) bool {
		if call.Kind != ir.NodeKindCall || len(call.Children) < 2 {
			return true
		}
		src, _ := call.Attrs["callee_src"].(string)
		name := lastSegment(src)
		fns := byName[name]
		if len(fns) == 0 || !argsCarryTaint(call.Children[len(call.Children)-1], pats, tainted) {
			return true
		}
		for _, fn := range fns {
			params, _ := fn.Attrs["parameters"].([]string)
			for _, p := range params {
				if p == "" || p == "_" || tainted[p] {
					continue
				}
				tainted[p] = true
				reasons[p] = "argument passed to " + name + "(...)"
				delete(weak, p)
				changed = true
			}
		}
		return true
	})
	return changed
}

// helperName is a function's callable name: its declared name, or the variable
// an arrow function or function expression is assigned to.
func helperName(fn *ir.IRNode) string {
	if n := functionName(fn); n != "" && fn.Parent != nil && fn.Parent.Kind != ir.NodeKindAssignment {
		return n
	}
	if fn.Parent != nil && fn.Parent.Kind == ir.NodeKindAssignment {
		if lhs, _ := fn.Parent.Attrs["lhs"].(string); lhs != "" {
			return lhs
		}
	}
	return functionName(fn)
}

// lastSegment returns the final name of a callee ("this.Run" and
// "$this->run" give Run and run; "Route::get" gives get).
func lastSegment(callee string) string {
	if i := strings.LastIndexAny(callee, ".>:"); i >= 0 {
		callee = callee[i+1:]
	}
	return strings.TrimSpace(callee)
}

// argsCarryTaint reports whether an argument container holds a tainted name or
// text matching a source pattern (an inline Request.Query["q"]).
func argsCarryTaint(args *ir.IRNode, pats languagePatterns, tainted map[string]bool) bool {
	if args.Kind == ir.NodeKindIdentifier && tainted[args.Text] {
		return true
	}
	for _, d := range ir.Descendants(args) {
		if d.Kind == ir.NodeKindIdentifier && tainted[d.Text] {
			return true
		}
	}
	return matchesAny(pats.Sources, leafText(args))
}

// leafText joins the text of a subtree's leaves, an approximation of its source
// without whitespace, good enough to match accessor patterns.
func leafText(n *ir.IRNode) string {
	var b strings.Builder
	var rec func(*ir.IRNode)
	rec = func(x *ir.IRNode) {
		if len(x.Children) == 0 {
			b.WriteString(x.Text)
			return
		}
		for _, c := range x.Children {
			rec(c)
		}
	}
	rec(n)
	return b.String()
}
