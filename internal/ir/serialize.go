package ir

import "github.com/zerostrike/scanner/internal/core"

// SerialNode is the flat, JSON-serializable form of one IRNode, used by the
// AST cache to persist parsed IR across scan runs. Unlike IRNode, it has no
// Parent pointer (rebuilt on load) and references children by index into
// the flat slice rather than by pointer.
type SerialNode struct {
	Kind     NodeKind
	Text     string
	NodeID   string
	Location core.Location
	Attrs    map[string]any
	Children []int
}

// FlattenIR converts file's IR tree into a flat, JSON-round-trippable slice
// in depth-first pre-order (see Walk) — index 0 is always the root. Returns
// nil for a nil file or nil file.Root.
func FlattenIR(file *IRFile) []SerialNode {
	if file == nil || file.Root == nil {
		return nil
	}

	// First pass: collect pointers in pre-order (matches Walk's visit order),
	// so index 0 is always the root.
	var order []*IRNode
	Walk(file.Root, func(node *IRNode) bool {
		order = append(order, node)
		return true
	})

	index := make(map[*IRNode]int, len(order))
	for i, node := range order {
		index[node] = i
	}

	// Second pass: build the flat SerialNode slice, translating child
	// pointers into indices via the lookup map built above.
	out := make([]SerialNode, len(order))
	for i, node := range order {
		var children []int
		if len(node.Children) > 0 {
			children = make([]int, len(node.Children))
			for j, child := range node.Children {
				children[j] = index[child]
			}
		}
		out[i] = SerialNode{
			Kind:     node.Kind,
			Text:     node.Text,
			NodeID:   node.NodeID,
			Location: node.Location,
			Attrs:    node.Attrs,
			Children: children,
		}
	}
	return out
}

// RebuildIR reconstructs an IRFile from a flat slice produced by FlattenIR
// (typically after a JSON marshal/unmarshal round-trip, e.g. from an AST
// cache entry read back from disk). lang and path repopulate the fields
// FlattenIR does not carry (they belong to IRFile, not IRNode). Returns nil
// for an empty nodes slice. Restores the known-typed Attrs keys listed in
// this file's package doc — see restoreAttrs below — so callers see the
// exact same concrete types the original parser builders produced, not
// JSON's default untyped-map/float64/[]interface{} shapes.
func RebuildIR(nodes []SerialNode, lang core.Language, path string) *IRFile {
	if len(nodes) == 0 {
		return nil
	}

	// First pass: construct one *IRNode per SerialNode, index-aligned.
	// Children/Parent are left unset here and wired up in the second pass,
	// since a node's children may appear later in the slice.
	built := make([]*IRNode, len(nodes))
	for i, sn := range nodes {
		built[i] = &IRNode{
			NodeID:   sn.NodeID,
			Kind:     sn.Kind,
			Text:     sn.Text,
			Location: sn.Location,
			Attrs:    restoreAttrs(sn.Attrs),
		}
	}

	// Second pass: resolve each node's Children index list into pointers
	// and set the back-reference Parent pointer on each child.
	for i, sn := range nodes {
		node := built[i]
		if len(sn.Children) == 0 {
			continue
		}
		node.Children = make([]*IRNode, len(sn.Children))
		for j, childIdx := range sn.Children {
			child := built[childIdx]
			node.Children[j] = child
			child.Parent = node
		}
	}

	return &IRFile{
		Language: lang,
		Path:     path,
		Root:     built[0],
	}
}

// restoreAttrs returns a copy of attrs with the handful of known Attrs keys
// whose value types do not survive a JSON marshal/unmarshal round-trip
// through the `any`-typed Attrs map coerced back to their correct concrete
// Go types:
//
//   - "argument_count": JSON unmarshals numbers into `any` as float64; the
//     original type set by parser builders is int.
//   - "parameters": JSON unmarshals into `any` as []interface{} of strings;
//     the original type is []string.
//   - "except_handlers": JSON unmarshals into `any` as []interface{} of
//     map[string]interface{}; the original type is []ir.ExceptHandler.
//
// Each coercion is defensive: if the value is already in the target
// concrete type (e.g. because attrs never actually went through a JSON
// round-trip, such as a test calling RebuildIR directly on FlattenIR's
// in-memory output), it is passed through unchanged rather than
// double-converted or dropped. Values of any other shape (e.g. malformed
// cache data) are left as-is rather than causing a panic.
//
// This is a manually maintained list, not a generic solution: if a parser
// builder starts setting a new Attrs key with a non-string/non-bool value
// type, add its restoration here too.
func restoreAttrs(attrs map[string]any) map[string]any {
	if attrs == nil {
		return nil
	}

	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}

	if v, ok := out["argument_count"]; ok {
		out["argument_count"] = coerceInt(v)
	}
	if v, ok := out["parameters"]; ok {
		out["parameters"] = coerceStringSlice(v)
	}
	if v, ok := out["except_handlers"]; ok {
		out["except_handlers"] = coerceExceptHandlers(v)
	}

	return out
}

// coerceInt normalizes a value that should be an int. Handles the
// already-correct int case (no JSON hop) and the JSON-round-tripped
// float64 case. Any other shape is returned unchanged.
func coerceInt(v any) any {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	default:
		return v
	}
}

// coerceStringSlice normalizes a value that should be []string. Handles
// the already-correct []string case (no JSON hop) and the
// JSON-round-tripped []interface{} case. Any other shape is returned
// unchanged.
func coerceStringSlice(v any) any {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return v
	}
}

// coerceExceptHandlers normalizes a value that should be []ExceptHandler.
// Handles the already-correct []ExceptHandler case (no JSON hop) and the
// JSON-round-tripped []interface{} of map[string]interface{} case, reading
// the "IsBare", "Types", and "IsEmptyBody" keys — the exact field names
// encoding/json uses by default for ExceptHandler's exported fields, since
// it has no json struct tags. Any other shape is returned unchanged.
func coerceExceptHandlers(v any) any {
	switch t := v.(type) {
	case []ExceptHandler:
		return t
	case []interface{}:
		out := make([]ExceptHandler, 0, len(t))
		for _, item := range t {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			var h ExceptHandler
			if isBare, ok := m["IsBare"].(bool); ok {
				h.IsBare = isBare
			}
			if isEmpty, ok := m["IsEmptyBody"].(bool); ok {
				h.IsEmptyBody = isEmpty
			}
			if types, ok := m["Types"]; ok {
				if coerced, ok := coerceStringSlice(types).([]string); ok {
					h.Types = coerced
				}
			}
			out = append(out, h)
		}
		return out
	default:
		return v
	}
}
