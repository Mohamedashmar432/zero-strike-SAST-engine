package sca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRequirementsTxt_Pinned(t *testing.T) {
	data := []byte("requests==2.31.0\nflask==2.3.2\n")
	deps := parseRequirementsTxt("requirements.txt", data)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	for _, d := range deps {
		if !d.Direct {
			t.Errorf("dep %s should be Direct", d.Package)
		}
		if d.Ecosystem != "PyPI" {
			t.Errorf("dep %s Ecosystem = %q, want PyPI", d.Package, d.Ecosystem)
		}
	}
	if deps[0].Package != "requests" || deps[0].Version != "2.31.0" {
		t.Errorf("first dep = %+v, want requests==2.31.0", deps[0])
	}
	if deps[1].Package != "flask" || deps[1].Version != "2.3.2" {
		t.Errorf("second dep = %+v, want flask==2.3.2", deps[1])
	}
}

func TestParseRequirementsTxt_Unpinned(t *testing.T) {
	data := []byte("requests>=2.0\nflask\n")
	deps := parseRequirementsTxt("requirements.txt", data)
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for unpinned, got %d: %+v", len(deps), deps)
	}
}

func TestParseRequirementsTxt_Comments(t *testing.T) {
	data := []byte("# this is a comment\nrequests==2.31.0\n# another comment\n")
	deps := parseRequirementsTxt("requirements.txt", data)
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Package != "requests" {
		t.Errorf("unexpected package %q", deps[0].Package)
	}
}

func TestParsePackageLockJSON_V2(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 2,
		"packages": {
			"": {},
			"node_modules/lodash": {"version": "4.17.20"},
			"node_modules/express": {"version": "4.18.2"}
		}
	}`)
	deps, err := parsePackageLockJSON("package-lock.json", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %+v", len(deps), deps)
	}
	names := map[string]string{}
	for _, d := range deps {
		names[d.Package] = d.Version
		if d.Ecosystem != "npm" {
			t.Errorf("dep %s Ecosystem = %q, want npm", d.Package, d.Ecosystem)
		}
	}
	if names["lodash"] != "4.17.20" {
		t.Errorf("lodash version = %q, want 4.17.20", names["lodash"])
	}
	if names["express"] != "4.18.2" {
		t.Errorf("express version = %q, want 4.18.2", names["express"])
	}
}

func TestParsePackageLockJSON_V1(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"lodash": {"version": "4.17.20"},
			"express": {"version": "4.18.2"}
		}
	}`)
	deps, err := parsePackageLockJSON("package-lock.json", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %+v", len(deps), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "npm" {
			t.Errorf("dep %s Ecosystem = %q, want npm", d.Package, d.Ecosystem)
		}
		if d.Version == "" {
			t.Errorf("dep %s has empty version", d.Package)
		}
	}
}

func TestParseYarnLock(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "yarn.lock"))
	if err != nil {
		t.Fatal(err)
	}
	deps := parseYarnLock("yarn.lock", data)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %+v", len(deps), deps)
	}
	byName := map[string]string{}
	for _, d := range deps {
		byName[d.Package] = d.Version
		if d.Ecosystem != "npm" {
			t.Errorf("dep %s Ecosystem = %q, want npm", d.Package, d.Ecosystem)
		}
	}
	if byName["lodash"] != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", byName["lodash"])
	}
	if byName["express"] != "4.18.2" {
		t.Errorf("express version = %q, want 4.18.2", byName["express"])
	}
}

func TestParsePnpmLock(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	deps := parsePnpmLock("pnpm-lock.yaml", data)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %+v", len(deps), deps)
	}
	byName := map[string]string{}
	for _, d := range deps {
		byName[d.Package] = d.Version
		if d.Ecosystem != "npm" {
			t.Errorf("dep %s Ecosystem = %q, want npm", d.Package, d.Ecosystem)
		}
	}
	if byName["lodash"] != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", byName["lodash"])
	}
	if byName["express"] != "4.18.2" {
		t.Errorf("express version = %q, want 4.18.2", byName["express"])
	}
}

func TestParseGoMod(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	deps := parseGoMod("go.mod", data)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	byName := map[string]Dependency{}
	for _, d := range deps {
		byName[d.Package] = d
		if d.Ecosystem != "Go" {
			t.Errorf("dep %s Ecosystem = %q, want Go", d.Package, d.Ecosystem)
		}
	}
	if byName["github.com/sirupsen/logrus"].Version != "v1.9.3" {
		t.Errorf("logrus version = %q, want v1.9.3", byName["github.com/sirupsen/logrus"].Version)
	}
	if !byName["github.com/sirupsen/logrus"].Direct {
		t.Errorf("logrus should be Direct=true")
	}
	if !byName["github.com/spf13/cobra"].Direct {
		t.Errorf("cobra should be Direct=true")
	}
	if byName["github.com/indirect-dep/lib"].Direct {
		t.Errorf("indirect-dep/lib should be Direct=false")
	}
}

func TestParsePomXML(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pom.xml"))
	if err != nil {
		t.Fatal(err)
	}
	deps := parsePomXML("pom.xml", data)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	byName := map[string]Dependency{}
	for _, d := range deps {
		byName[d.Package] = d
		if d.Ecosystem != "Maven" {
			t.Errorf("dep %s Ecosystem = %q, want Maven", d.Package, d.Ecosystem)
		}
	}
	if byName["org.apache.commons:commons-lang3"].Version != "3.12.0" {
		t.Errorf("commons-lang3 version = %q, want 3.12.0", byName["org.apache.commons:commons-lang3"].Version)
	}
	if !byName["org.apache.commons:commons-lang3"].Direct {
		t.Errorf("commons-lang3 should be Direct=true")
	}
	if byName["com.fasterxml.jackson.core:jackson-databind"].Version != "2.15.2" {
		t.Errorf("jackson-databind version = %q, want 2.15.2 (resolved from ${jackson.version})", byName["com.fasterxml.jackson.core:jackson-databind"].Version)
	}
	if byName["org.springframework:spring-core"].Direct {
		t.Errorf("spring-core (dependencyManagement) should be Direct=false")
	}
}

func TestResolveMavenVersion_Range(t *testing.T) {
	got := resolveMavenVersion("[1.5,2.0)", nil)
	if got != "1.5" {
		t.Errorf("resolveMavenVersion(range) = %q, want 1.5", got)
	}
}

func TestResolveMavenVersion_UnresolvedProperty(t *testing.T) {
	got := resolveMavenVersion("${missing.version}", map[string]string{})
	if got != "" {
		t.Errorf("resolveMavenVersion(unresolved property) = %q, want empty", got)
	}
}

func TestParsePipfileLock(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Pipfile.lock"))
	if err != nil {
		t.Fatal(err)
	}
	deps := parsePipfileLock("Pipfile.lock", data)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	byName := map[string]Dependency{}
	for _, d := range deps {
		byName[d.Package] = d
	}
	if byName["requests"].Version != "2.28.0" {
		t.Errorf("requests version = %q, want 2.28.0", byName["requests"].Version)
	}
	if byName["requests"].Ecosystem != "PyPI" {
		t.Errorf("requests Ecosystem = %q, want PyPI", byName["requests"].Ecosystem)
	}
	if !byName["requests"].Direct {
		t.Errorf("requests should be Direct=true")
	}
	if byName["pytest"].Direct {
		t.Errorf("pytest (develop dep) should be Direct=false")
	}
}
