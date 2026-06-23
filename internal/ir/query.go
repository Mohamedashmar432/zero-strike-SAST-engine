package ir

// Walk traverses the IR tree in depth-first pre-order.
// fn receives each node; returning false stops traversal of that subtree.
func Walk(root *IRNode, fn func(node *IRNode) bool) {
	if root == nil || fn == nil {
		return
	}
	if !fn(root) {
		return
	}
	for _, child := range root.Children {
		Walk(child, fn)
	}
}

// FindByKind returns all nodes of the given kind in the subtree.
func FindByKind(root *IRNode, kind NodeKind) []*IRNode {
	var results []*IRNode
	Walk(root, func(node *IRNode) bool {
		if node.Kind == kind {
			results = append(results, node)
		}
		return true
	})
	return results
}

// FindByText returns all nodes whose Text matches the given string.
func FindByText(root *IRNode, text string) []*IRNode {
	var results []*IRNode
	Walk(root, func(node *IRNode) bool {
		if node.Text == text {
			results = append(results, node)
		}
		return true
	})
	return results
}

// Ancestors returns the ancestor chain from node up to root (exclusive of node itself).
// The slice is ordered from the immediate parent up to the topmost ancestor.
func Ancestors(node *IRNode) []*IRNode {
	if node == nil {
		return nil
	}
	var chain []*IRNode
	cur := node.Parent
	for cur != nil {
		chain = append(chain, cur)
		cur = cur.Parent
	}
	return chain
}

// Descendants returns all descendant nodes of root (not including root itself).
func Descendants(root *IRNode) []*IRNode {
	var results []*IRNode
	first := true
	Walk(root, func(node *IRNode) bool {
		if first {
			first = false
			return true
		}
		results = append(results, node)
		return true
	})
	return results
}

// FindCalls returns all call nodes in the subtree where the callee text matches callee.
// For example, FindCalls(root, "eval") finds all eval(...) calls.
func FindCalls(root *IRNode, callee string) []*IRNode {
	var results []*IRNode
	Walk(root, func(node *IRNode) bool {
		if node.Kind != NodeKindCall {
			return true
		}
		for _, child := range node.Children {
			if child.Kind == NodeKindIdentifier && child.Text == callee {
				results = append(results, node)
				return true
			}
		}
		return true
	})
	return results
}
