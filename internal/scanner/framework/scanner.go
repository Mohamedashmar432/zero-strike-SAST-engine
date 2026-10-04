package framework

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// check is one framework-misconfiguration detector. Each check owns its
// own file matcher and detect function, mirroring internal/scanner/secrets'
// detectors table.
type check struct {
	ruleID  string
	accepts func(path string) bool
	detect  func(path string, data []byte) []core.Finding
}

var checks = []check{
	djangoDebugCheck,
	expressHelmetCheck,
	corsWildcardCheck,
	laravelDebugCheck,
	springActuatorExposedCheck,
	springCookieInsecureCheck,
	aspnetVerboseErrorsCheck,
	aspnetDirectoryBrowseCheck,
	laravelSessionCookieCheck,
	laravelCsrfExceptCheck,
	phpIniCookieInsecureCheck,
	githubActionsUnpinnedCheck,
	dockerComposePrivilegedCheck,
}

// FrameworkScanner detects framework-level security misconfigurations by
// reading config files directly. Pure Go — no CGo, no tree-sitter/IR.
type FrameworkScanner struct {
	rootPath string // scan root; fingerprints hash paths relative to it
}

// New returns a FrameworkScanner. rootPath is the scan root, used only to
// make finding fingerprints independent of the checkout location.
func New(rootPath string) *FrameworkScanner { return &FrameworkScanner{rootPath: rootPath} }

// fingerprintPath returns path relative to the scan root with forward slashes.
// Paths outside the root (or with no root set) are only slash-normalised,
// which leaves already-relative paths unchanged on POSIX.
func (s *FrameworkScanner) fingerprintPath(path string) string {
	if s.rootPath != "" {
		if rel, err := filepath.Rel(s.rootPath, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = rel
		}
	}
	return filepath.ToSlash(path)
}

func (s *FrameworkScanner) Name() string { return "framework" }

func (s *FrameworkScanner) Accepts(entry walker.FileEntry) bool {
	if entry.IsBinary {
		return false
	}
	for _, c := range checks {
		if c.accepts(entry.Path) {
			return true
		}
	}
	return false
}

func (s *FrameworkScanner) Scan(_ context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	var out []core.Finding
	for _, entry := range files {
		data, err := os.ReadFile(entry.Path)
		if err != nil {
			continue
		}
		for _, c := range checks {
			if !c.accepts(entry.Path) {
				continue
			}
			for _, f := range c.detect(entry.Path, data) {
				if f.Config != nil {
					f.Fingerprint = findings.ConfigFingerprint(f.RuleID, s.fingerprintPath(f.Config.ConfigFile), f.Config.Key)
				}
				out = append(out, f)
			}
		}
	}
	return out, nil, nil
}

// isEnvFile matches ".env", ".env.<suffix>", and "*.env" file names.
func isEnvFile(path string) bool {
	base := strings.ToLower(baseName(path))
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// nonProdEnvSuffixes is the standard dotenv convention for non-production
// files — findings on these are suppressed to avoid flagging test/example
// fixtures as if they were real production config.
var nonProdEnvSuffixes = []string{
	".local", ".dev", ".development", ".test", ".testing",
	".example", ".sample", ".dist",
}

// isLikelyNonProdEnvFile reports whether path's name signals a non-production
// env file by the standard dotenv suffix convention (.env.local, .env.example, ...).
func isLikelyNonProdEnvFile(path string) bool {
	base := strings.ToLower(baseName(path))
	for _, suffix := range nonProdEnvSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// envValueIsTruthy reports whether a dotenv-style value represents "true".
func envValueIsTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// envValueIsNonProd reports whether an APP_ENV/ENVIRONMENT-style value
// signals a non-production environment.
func envValueIsNonProd(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "local", "development", "dev", "testing", "test":
		return true
	default:
		return false
	}
}

func findEnvValue(entries []EnvEntry, key string) (EnvEntry, bool) {
	for _, e := range entries {
		if e.Key == key {
			return e, true
		}
	}
	return EnvEntry{}, false
}
