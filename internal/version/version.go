// SPDX-License-Identifier: Apache-2.0

// Package version is the single source of truth for the ZeroStrike engine
// version, shared by cmd/zerostrike and cmd/zerostrike-bench (and, later,
// the disk cache's version-based invalidation).
package version

import "strconv"

// Version is the ZeroStrike engine version, overridden at build time via
// -ldflags "-X .../internal/version.Version=$TAG" for tagged releases.
// Defaults to "dev" for local/untagged builds.
var Version = "dev"

// MatchSemanticsRevision is bumped by hand whenever a change to the Go side of
// matching can produce different findings for byte-identical source: taint
// tiering, a new filter, file-role classification, inline suppression.
//
// It exists because the finding cache keys on EngineVersion, and Version alone
// cannot carry this. Version is injected at build time and stays "dev" for
// every local and CI build, so two binaries with materially different matching
// semantics were indistinguishable to the cache: the first scan after an
// upgrade served pre-change findings from disk. The rule-set hash does not
// cover it either, since that hashes only rule YAML.
//
// Revision history:
//
//	1 - baseline
//	2 - precision overhaul: file-role filtering, retired-rule enforcement,
//	    weak/strong taint tiering, argument_kind_not_at, inline suppressions,
//	    generic-detector secret filters, cross-engine credential dedup
const MatchSemanticsRevision = 2

// CacheKey returns the identity the finding and IR caches must key on, pairing
// the release version with the matching-semantics revision so that either one
// changing invalidates cached findings.
func CacheKey() string {
	return Version + "+match" + strconv.Itoa(MatchSemanticsRevision)
}
