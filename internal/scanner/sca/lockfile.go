package sca

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"regexp"
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
	deps, _ := parseLockFileWithErr(path, data)
	return deps
}

// parseLockFileWithErr dispatches to the appropriate parser, returning any parsing error.
func parseLockFileWithErr(path string, data []byte) ([]Dependency, error) {
	base := filepath.Base(path)
	switch {
	case base == "package-lock.json":
		return parsePackageLockJSON(path, data)
	case base == "package.json":
		return parsePackageJSON(path, data)
	case base == "yarn.lock":
		return parseYarnLock(path, data), nil
	case base == "pnpm-lock.yaml":
		return parsePnpmLock(path, data), nil
	case base == "Pipfile.lock":
		return parsePipfileLock(path, data), nil
	case base == "go.mod":
		return parseGoMod(path, data), nil
	case base == "pom.xml":
		return parsePomXML(path, data), nil
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return parseRequirementsTxt(path, data), nil
	case base == "packages.lock.json":
		return parseNuGetLock(path, data)
	case isDotnetProject(base), base == "Directory.Packages.props", base == "Directory.Build.props":
		return parseMSBuildPackages(path, data)
	case strings.EqualFold(base, "packages.config"):
		return parsePackagesConfig(path, data)
	}
	return nil, nil
}

// isDotnetProject reports whether base is an SDK-style or legacy .NET project file.
func isDotnetProject(base string) bool {
	ext := strings.ToLower(filepath.Ext(base))
	return ext == ".csproj" || ext == ".fsproj" || ext == ".vbproj"
}

// parseNuGetLock parses a NuGet packages.lock.json (RestorePackagesWithLockFile). It holds the
// resolved version of every package, transitive ones included, per target framework -- the
// authoritative answer whenever it exists, which is why a project file beside it is skipped.
func parseNuGetLock(path string, data []byte) ([]Dependency, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var deps []Dependency
	for _, framework := range lock.Dependencies {
		for name, entry := range framework {
			if name == "" || entry.Resolved == "" || entry.Type == "Project" {
				continue // "Project" entries are sibling projects in the solution, not packages
			}
			deps = append(deps, Dependency{
				Ecosystem: "NuGet",
				Package:   name,
				Version:   entry.Resolved,
				Manifest:  path,
				Direct:    entry.Type == "Direct",
			})
		}
	}
	return deps, nil
}

// parseMSBuildPackages reads <PackageReference> from a project file, and <PackageVersion> from
// Directory.Packages.props (central package management, where the project files carry no versions
// at all). Both the attribute form (Version="1.2.3") and the child-element form are accepted.
func parseMSBuildPackages(path string, data []byte) ([]Dependency, error) {
	type ref struct {
		Include   string `xml:"Include,attr"`
		Update    string `xml:"Update,attr"`
		Version   string `xml:"Version,attr"`
		VersionEl string `xml:"Version"`
	}
	var proj struct {
		ItemGroups []struct {
			PackageReference []ref `xml:"PackageReference"`
			PackageVersion   []ref `xml:"PackageVersion"`
		} `xml:"ItemGroup"`
	}
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}
	var deps []Dependency
	add := func(r ref) {
		name := strings.TrimSpace(r.Include)
		if name == "" {
			name = strings.TrimSpace(r.Update)
		}
		version := exactNuGetVersion(r.Version)
		if version == "" {
			version = exactNuGetVersion(r.VersionEl)
		}
		if name == "" || version == "" {
			return
		}
		deps = append(deps, Dependency{Ecosystem: "NuGet", Package: name, Version: version, Manifest: path, Direct: true})
	}
	for _, g := range proj.ItemGroups {
		for _, r := range g.PackageReference {
			add(r)
		}
		for _, r := range g.PackageVersion {
			add(r)
		}
	}
	return deps, nil
}

// parsePackagesConfig parses the legacy (.NET Framework) packages.config.
func parsePackagesConfig(path string, data []byte) ([]Dependency, error) {
	var cfg struct {
		Packages []struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr"`
		} `xml:"package"`
	}
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	var deps []Dependency
	for _, p := range cfg.Packages {
		if v := exactNuGetVersion(p.Version); p.ID != "" && v != "" {
			deps = append(deps, Dependency{Ecosystem: "NuGet", Package: p.ID, Version: v, Manifest: path, Direct: true})
		}
	}
	return deps, nil
}

// exactNuGetVersion returns v when it names one concrete version ("12.0.1", or the exact-match
// range "[12.0.1]"), and "" for anything OSV cannot be asked about: an open range ("[1.0,2.0)"),
// a floating version ("1.*") or an unexpanded MSBuild property ("$(JsonVersion)").
func exactNuGetVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !strings.Contains(v, ",") {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if v == "" || strings.ContainsAny(v, "*$(),[]") {
		return ""
	}
	return v
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

var semverCleanRe = regexp.MustCompile(`^[\^~>=<v\s]*(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)`)

func cleanSemverSpec(spec string) string {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "/") || strings.Contains(spec, ":") || spec == "*" || spec == "latest" {
		return ""
	}
	m := semverCleanRe.FindStringSubmatch(spec)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// parsePackageJSON parses a npm package.json manifest.
func parsePackageJSON(path string, data []byte) ([]Dependency, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency
	extractDeps := func(m map[string]string) {
		for name, spec := range m {
			if name == "" || spec == "" {
				continue
			}
			ver := cleanSemverSpec(spec)
			if ver == "" {
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
	}
	extractDeps(pkg.Dependencies)
	extractDeps(pkg.DevDependencies)
	return deps, nil
}

// parsePackageLockJSON parses npm package-lock.json (v1, v2, v3).
func parsePackageLockJSON(path string, data []byte) ([]Dependency, error) {
	type v1Dep struct {
		Version      string           `json:"version"`
		Dependencies map[string]v1Dep `json:"dependencies"`
	}
	var raw struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v1 format
		Dependencies map[string]v1Dep `json:"dependencies"`
		// v2/v3 format
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var deps []Dependency
	if raw.LockfileVersion <= 1 || (len(raw.Packages) == 0 && len(raw.Dependencies) > 0) {
		var collectV1 func(depsMap map[string]v1Dep, isDirect bool)
		collectV1 = func(depsMap map[string]v1Dep, isDirect bool) {
			for name, entry := range depsMap {
				if name == "" || entry.Version == "" {
					continue
				}
				deps = append(deps, Dependency{
					Ecosystem: "npm",
					Package:   name,
					Version:   entry.Version,
					Manifest:  path,
					Direct:    isDirect,
				})
				if len(entry.Dependencies) > 0 {
					collectV1(entry.Dependencies, false)
				}
			}
		}
		collectV1(raw.Dependencies, true)
	} else {
		for key, entry := range raw.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			// In npm v2/v3, keys are "node_modules/foo" or "node_modules/foo/node_modules/bar" or "node_modules/@scope/pkg"
			idx := strings.LastIndex(key, "node_modules/")
			if idx == -1 {
				continue
			}
			name := key[idx+len("node_modules/"):]
			if name == "" {
				continue
			}
			isDirect := (idx == 0)
			deps = append(deps, Dependency{
				Ecosystem: "npm",
				Package:   name,
				Version:   entry.Version,
				Manifest:  path,
				Direct:    isDirect,
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
				ver = trimmed[len(`version "`) : len(trimmed)-1]
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

// mavenPOM is the subset of a Maven pom.xml this parser cares about.
type mavenPOM struct {
	Properties struct {
		Entries []mavenProperty `xml:",any"`
	} `xml:"properties"`
	Dependencies struct {
		Dependency []mavenDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []mavenDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

// mavenProperty captures one <properties> child element by its tag name
// (e.g. <foo.version>1.2.3</foo.version>), used to resolve ${foo.version}
// placeholders in dependency versions.
type mavenProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// parsePomXML parses a Maven pom.xml, extracting <dependencies> as direct
// and <dependencyManagement> as indirect/managed — mirroring parseGoMod's
// direct/indirect split. Package names are groupId:artifactId, matching
// OSV's Maven ecosystem convention.
func parsePomXML(path string, data []byte) []Dependency {
	var pom mavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil
	}
	props := make(map[string]string, len(pom.Properties.Entries))
	for _, p := range pom.Properties.Entries {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}
	var deps []Dependency
	for _, d := range pom.Dependencies.Dependency {
		if dep := buildMavenDependency(d, props, path, true); dep != nil {
			deps = append(deps, *dep)
		}
	}
	for _, d := range pom.DependencyManagement.Dependencies.Dependency {
		if dep := buildMavenDependency(d, props, path, false); dep != nil {
			deps = append(deps, *dep)
		}
	}
	return deps
}

func buildMavenDependency(d mavenDependency, props map[string]string, path string, direct bool) *Dependency {
	groupID := strings.TrimSpace(d.GroupID)
	artifactID := strings.TrimSpace(d.ArtifactID)
	if groupID == "" || artifactID == "" {
		return nil
	}
	version := resolveMavenVersion(strings.TrimSpace(d.Version), props)
	if version == "" {
		return nil
	}
	return &Dependency{
		Ecosystem: "Maven",
		Package:   groupID + ":" + artifactID,
		Version:   version,
		Manifest:  path,
		Direct:    direct,
	}
}

var (
	mavenPropertyPattern     = regexp.MustCompile(`\$\{([^}]+)\}`)
	mavenRangeVersionPattern = regexp.MustCompile(`[0-9][0-9A-Za-z.\-]*`)
)

// resolveMavenVersion substitutes a ${property} placeholder from this pom's
// own <properties> block (no parent-POM or multi-module reactor inheritance
// — out of scope for this sprint's narrow exit criteria) and reduces a
// Maven version range ([1.0,2.0), [1.5,)) to its first concrete version
// bound, since OSV's API takes an exact version, not a range. Returns ""
// when the version can't be resolved, matching parseRequirementsTxt's
// "skip unpinned" convention.
func resolveMavenVersion(raw string, props map[string]string) string {
	if raw == "" {
		return ""
	}
	if m := mavenPropertyPattern.FindStringSubmatch(raw); m != nil {
		resolved, ok := props[strings.TrimSpace(m[1])]
		if !ok {
			return ""
		}
		raw = resolved
	}
	if strings.ContainsAny(raw, "[](),") {
		return mavenRangeVersionPattern.FindString(raw)
	}
	return raw
}

// deduplicateDeps removes duplicate (ecosystem, package, version) entries.
func deduplicateDeps(deps []Dependency) []Dependency {
	seen := make(map[string]struct{}, len(deps))
	out := deps[:0]
	for _, d := range deps {
		// Per manifest: the same vulnerable package in two sub-projects is two places to fix, and
		// each must be reported against its own manifest.
		key := d.Ecosystem + "|" + d.Package + "|" + d.Version + "|" + d.Manifest
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}
