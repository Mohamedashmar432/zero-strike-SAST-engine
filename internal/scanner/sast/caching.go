package sast

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// This file holds the pure, parser-independent half of the SAST scanner's
// caching logic (hashing, and AST-cache (de)serialization). It carries no
// //go:build tag - unlike sast.go, which is cgo-only because it links the
// tree-sitter-backed parser packages - so this logic is exercised by
// caching_test.go even in CGo-less environments/CI that cannot build a real
// SASTScanner or run processFile end-to-end.

// sha256Hex returns the hex-encoded SHA-256 digest of data, used as the
// cache key for both the finding cache and the AST cache.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// decodeCachedIR attempts to reconstruct an *ir.IRFile from AST-cache bytes
// (a JSON-encoded []ir.SerialNode, as produced by encodeIR/ir.FlattenIR). It
// returns ok=false for any data that fails to unmarshal or fails to rebuild
// into a non-empty tree, so that a corrupted or schema-incompatible AST
// cache entry degrades to a cache miss (triggering a fresh parse) rather
// than failing the file.
func decodeCachedIR(data []byte, lang core.Language, path string) (*ir.IRFile, bool) {
	var nodes []ir.SerialNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, false
	}
	irFile := ir.RebuildIR(nodes, lang, path)
	if irFile == nil {
		return nil, false
	}
	return irFile, true
}

// encodeIR serializes irFile (via ir.FlattenIR) into the bytes stored by the
// AST cache. It returns ok=false when there is nothing worth caching (a nil
// file, or one FlattenIR can't flatten) or if marshaling fails.
func encodeIR(irFile *ir.IRFile) ([]byte, bool) {
	nodes := ir.FlattenIR(irFile)
	if nodes == nil {
		return nil, false
	}
	data, err := json.Marshal(nodes)
	if err != nil {
		return nil, false
	}
	return data, true
}
