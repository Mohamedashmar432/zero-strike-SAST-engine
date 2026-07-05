package rules

import "embed"

// EmbeddedFS holds the built-in rule packs. Go requires go:embed patterns to
// be compile-time literals, so adding a language means adding its glob here
// (and its dir to RuleDirs below) — this is the one manual step langreg
// cannot absorb.
//
//go:embed data/python/*.yaml data/js/*.yaml data/ts/*.yaml data/csharp/*.yaml data/go/*.yaml data/php/*.yaml data/java/*.yaml
var EmbeddedFS embed.FS

// RuleDirs lists every embedded rule directory. Consumers (e.g. the pipeline
// rule loader) iterate this instead of maintaining their own copies.
var RuleDirs = []string{"data/python", "data/js", "data/ts", "data/csharp", "data/go", "data/php", "data/java"}
