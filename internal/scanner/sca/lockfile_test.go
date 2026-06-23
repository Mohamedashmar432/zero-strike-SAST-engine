package sca

import (
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
