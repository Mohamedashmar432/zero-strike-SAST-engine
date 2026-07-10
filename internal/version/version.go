// SPDX-License-Identifier: Apache-2.0

// Package version is the single source of truth for the ZeroStrike engine
// version, shared by cmd/zerostrike and cmd/zerostrike-bench (and, later,
// the disk cache's version-based invalidation).
package version

// Version is the ZeroStrike engine version, overridden at build time via
// -ldflags "-X .../internal/version.Version=$TAG" for tagged releases.
// Defaults to "dev" for local/untagged builds.
var Version = "dev"
