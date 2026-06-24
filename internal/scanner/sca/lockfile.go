package sca

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Dependency is a resolved package version from a lock file.
type Dependency struct {
	Ecosystem string
	Package   string
	Version   string
	Manifest  string
	Direct    bool
}

// parseLockFile dispatches to the appropriate parser based on file name.
func parseLockFile(path string, data []byte) []Dependency {
	base := filepath.Base(path)
	switch {
	case base == "package-lock.json":
		deps, _ := parsePackageLockJSON(path, data)
		return deps
	case base == "yarn.lock":
		return parseYarnLock(path, data)
	case base == "pnpm-lock.yaml":
		return parsePnpmLock(path, data)
	case base == "Pipfile.lock":
		return parsePipfileLock(path, data)
	case base == "go.mod":
		return parseGoMod(path, data)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return parseRequirementsTxt(path, data)
	}
	return nil
}

// parseRequirementsTxt parses a pip requirements.txt file.
// Only pinned dependencies (using ==) are included.
func parseRequirementsTxt(path string, data []byte) []Dependency {
	var deps []Dependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "-e") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue // unpinned or other specifier
		}
		pkg := strings.TrimSpace(parts[0])
		ver := strings.TrimSpace(parts[1])
		if pkg == "" || ver == "" {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem: "PyPI",
			Package:   pkg,
			Version:   ver,
			Manifest:  path,
			Direct:    true,
		})
	}
	return deps
}

// parsePackageLockJSON parses npm package-lock.json (v1, v2, v3).
func parsePackageLockJSON(path string, data []byte) ([]Dependency, error) {
	var raw struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v1 format
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
		// v2/v3 format
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var deps []Dependency
	if raw.LockfileVersion <= 1 {
		for name, entry := range raw.Dependencies {
			if name == "" || entry.Version == "" {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem: "npm",
				Package:   name,
				Version:   entry.Version,
				Manifest:  path,
				Direct:    !strings.Contains(name, "/"),
			})
		}
	} else {
		for key, entry := range raw.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			// Strip "node_modules/" prefix to get package name
			name := strings.TrimPrefix(key, "node_modules/")
			if name == "" {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem: "npm",
				Package:   name,
				Version:   entry.Version,
				Manifest:  path,
				Direct:    !strings.Contains(name, "node_modules/"),
			})
		}
	}
	return deps, nil
}

// parseYarnLock parses yarn.lock v1 (classic) and v2 (Berry) formats.
func parseYarnLock(path string, data []byte) []Dependency {
	var deps []Dependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	var currentPkg string
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			currentPkg = ""
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Non-indented line ending in ":" → new package block header
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			currentPkg = extractYarnPkgName(trimmed)
			continue
		}
		// Version line: v1 → `version "x.y.z"`, v2 → `version: x.y.z`
		if currentPkg != "" && currentPkg != "__metadata" && strings.HasPrefix(trimmed, "version") {
			var ver string
			switch {
			case strings.HasPrefix(trimmed, `version "`) && strings.HasSuffix(trimmed, `"`):
				ver = trimmed[len(`version "`): len(trimmed)-1]
			case strings.HasPrefix(trimmed, "version: "):
				ver = strings.Trim(strings.TrimPrefix(trimmed, "version: "), `"`)
			}
			if ver = strings.TrimSpace(ver); ver != "" {
				deps = append(deps, Dependency{
					Ecosystem: "npm",
					Package:   currentPkg,
					Version:   ver,
					Manifest:  path,
					Direct:    true,
				})
				currentPkg = "" // one version per block
			}
		}
	}
	return deps
}

// extractYarnPkgName derives a package name from a yarn.lock block header line.
func extractYarnPkgName(header string) string {
	name := strings.TrimSuffix(header, ":")
	name = strings.Trim(name, `"`)
	// comma-separated aliases ("pkg@^1, pkg@~1"): take first
	if idx := strings.Index(name, ","); idx >= 0 {
		name = strings.TrimSpace(strings.Trim(name[:idx], `"`))
	}
	// strip version specifier: last "@" (idx>0 preserves scoped @scope/name)
	if idx := strings.LastIndex(name, "@"); idx > 0 {
		name = name[:idx]
	}
	return strings.TrimSpace(name)
}

// parsePnpmLock parses pnpm-lock.yaml (v6 and v9 formats).
func parsePnpmLock(path string, data []byte) []Dependency {
	var lock struct {
		Packages map[string]interface{} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	deps := make([]Dependency, 0, len(lock.Packages))
	for key := range lock.Packages {
		// v6 key: /package@version  v9 key: package@version
		k := strings.TrimPrefix(key, "/")
		idx := strings.LastIndex(k, "@")
		if idx <= 0 {
			continue
		}
		name, ver := k[:idx], k[idx+1:]
		if name == "" || ver == "" {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem: "npm",
			Package:   name,
			Version:   ver,
			Manifest:  path,
			Direct:    true,
		})
	}
	return deps
}

// parsePipfileLock parses a Pipfile.lock (JSON) produced by pipenv.
// "default" deps are marked Direct=true; "develop" deps Direct=false.
func parsePipfileLock(path string, data []byte) []Dependency {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	deps := make([]Dependency, 0, len(lock.Default)+len(lock.Develop))
	for pkg, info := range lock.Default {
		ver := strings.TrimPrefix(info.Version, "==")
		if ver == "" {
			continue
		}
		deps = append(deps, Dependency{Ecosystem: "PyPI", Package: pkg, Version: ver, Manifest: path, Direct: true})
	}
	for pkg, info := range lock.Develop {
		ver := strings.TrimPrefix(info.Version, "==")
		if ver == "" {
			continue
		}
		deps = append(deps, Dependency{Ecosystem: "PyPI", Package: pkg, Version: ver, Manifest: path, Direct: false})
	}
	return deps
}

// parseGoMod parses a go.mod file and extracts require directives.
// Direct dependencies (no "// indirect" comment) are marked Direct=true.
func parseGoMod(path string, data []byte) []Dependency {
	var deps []Dependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if line == ")" {
			inBlock = false
			continue
		}
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock {
			if d := parseGoModRequireLine(line, path); d != nil {
				deps = append(deps, *d)
			}
			continue
		}
		if rest, ok := strings.CutPrefix(line, "require "); ok {
			if d := parseGoModRequireLine(rest, path); d != nil {
				deps = append(deps, *d)
			}
		}
	}
	return deps
}

// parseGoModRequireLine parses a single require entry: "module v1.2.3 [// indirect]"
func parseGoModRequireLine(line, manifest string) *Dependency {
	indirect := strings.Contains(line, "// indirect")
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return nil
	}
	return &Dependency{
		Ecosystem: "Go",
		Package:   parts[0],
		Version:   parts[1],
		Manifest:  manifest,
		Direct:    !indirect,
	}
}

// deduplicateDeps removes duplicate (ecosystem, package, version) entries.
func deduplicateDeps(deps []Dependency) []Dependency {
	seen := make(map[string]struct{}, len(deps))
	out := deps[:0]
	for _, d := range deps {
		key := d.Ecosystem + "|" + d.Package + "|" + d.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}
