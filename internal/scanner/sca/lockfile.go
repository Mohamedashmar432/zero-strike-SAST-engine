package sca

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
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
