package cache

// ASTCache stores serialized IRFile objects to skip re-parsing unchanged files.
// It is intentionally unimplemented until Sprint 7.
//
// C8 design constraints (lock these in before implementing):
//
//  1. FLAT SERIALIZATION: Serialize a []SerialNode with integer child indices.
//     Do NOT serialize the Parent pointer — it is a cycle and makes gob slow.
//     Rebuild Parent pointers on load with a single O(n) pass over the slice.
//
//  2. TYPED ATTRS: Replace IRNode.Attrs map[string]any with a typed struct:
//     type NodeAttrs struct { ArgumentCount int; IsAsync bool; IsKeyword bool }
//     This eliminates the need for gob.Register on every concrete Attrs type.
//
//  3. CACHE KEY: SHA256(file content) — skip re-parse if hash unchanged.
//
//  4. VALIDATION: Store IR schema version alongside the cache entry.
//     Invalidate on schema version bump to avoid deserializing stale IR.
type ASTCache interface {
	GetIR(filePath, contentHash string) ([]byte, bool)
	SetIR(filePath, contentHash string, data []byte) error
}
