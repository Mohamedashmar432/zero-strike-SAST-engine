package pipeline

import "github.com/zerostrike/scanner/internal/core"

// ScanConfig holds all configuration for a single scan run.
type ScanConfig struct {
	RootPath     string
	Languages    []core.Language // empty = detect all
	OutputFormat string          // "json" | "sarif" | "html"
	OutputFile   string          // "" = stdout
	RulesDir     string          // "" = use embedded rules
	WorkerCount  int             // 0 = runtime.NumCPU()
	EnableGraphs bool
	NoCache      bool
	EnableSecrets bool
	EnableSCA     bool
	SCAOnError    string // "warn" (default) | "fail"
}
