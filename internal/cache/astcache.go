package cache

// ASTCache stores serialized IRFile objects to skip re-parsing unchanged
// files. Implemented by DiskASTCache (internal/cache/diskastcache.go) and
// NoopASTCache (internal/cache/noop.go), wired into
// internal/scanner/sast/sast.go's processFile.
//
// C8 design constraints (as actually implemented in internal/ir/serialize.go
// — this comment previously sketched a gob/typed-Attrs design before that
// package existed; it's updated here to match the real implementation
// rather than left to silently disagree with it):
//
//  1. FLAT SERIALIZATION: ir.FlattenIR/ir.RebuildIR serialize a
//     []ir.SerialNode with integer child indices via encoding/json (not
//     gob — JSON round-trips map[string]any natively, avoiding gob's
//     per-concrete-type registration entirely, which was constraint 2's
//     original goal). The Parent pointer is never serialized — it is a
//     cycle — and is rebuilt with a single O(n) pass over the slice on load.
//
//  2. ATTRS STAY map[string]any: rather than replacing IRNode.Attrs with a
//     typed struct, ir.RebuildIR's restoreAttrs coerces the handful of
//     Attrs keys whose concrete type doesn't survive a JSON round-trip
//     (argument_count, parameters, except_handlers) back to their original
//     Go types. This is a manually maintained list, not a generic solution
//     — see restoreAttrs's doc comment in internal/ir/serialize.go before
//     adding a new non-string/non-bool Attrs key anywhere in a parser
//     builder, or its type will silently fail to round-trip through a
//     cached-and-reloaded IR tree.
//
//  3. CACHE KEY: SHA256(file content) — skip re-parse if hash unchanged.
//
//  4. VALIDATION: Store IR schema version alongside the cache entry.
//     Invalidate on schema version bump to avoid deserializing stale IR.
type ASTCache interface {
	GetIR(filePath, contentHash string) ([]byte, bool)
	SetIR(filePath, contentHash string, data []byte) error
}
