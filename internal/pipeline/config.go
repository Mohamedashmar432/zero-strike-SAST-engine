package pipeline

import "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

// ScanConfig holds all configuration for a single scan run.
type ScanConfig struct {
	RootPath              string
	Languages             []core.Language // empty = detect all
	OutputFormat          string          // "json" | "sarif" | "html"
	OutputFile            string          // "" = stdout
	RulesDir              string          // "" = use embedded rules
	WorkerCount           int             // 0 = runtime.NumCPU()
	EnableGraphs          bool
	NoCache               bool
	EnableSecrets         bool
	EnableSCA             bool
	SCAOnError            string // "warn" (default) | "fail"
	EnableFrameworkChecks bool
	AllowFile             string   // path to .zs-allow.yaml; "" = auto-discover from RootPath
	ExcludeDirs           []string // extra directory names to skip (merged with hardcoded defaults)

	// IncludeTests scans files classified as test/fixture material
	// (walker.RoleTest) instead of skipping them. Off by default: production
	// rule semantics do not hold in a test path, where an assertion or a
	// fixture credential is the point rather than a defect.
	IncludeTests bool

	// IncludeHardening keeps findings of the hardening and quality tiers (see
	// core.Tier) in the output. Off by default: those findings carry no
	// exploit path of their own. They are never dropped silently -- the
	// pipeline counts every excluded finding per rule in
	// ScanResult.TierExcluded / TierExcludedByRule.
	IncludeHardening bool
}
