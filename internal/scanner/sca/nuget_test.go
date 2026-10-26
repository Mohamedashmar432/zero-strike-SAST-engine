package sca

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

func depNames(deps []Dependency) []string {
	var out []string
	for _, d := range deps {
		out = append(out, d.Package+"@"+d.Version)
	}
	sort.Strings(out)
	return out
}

func TestParseCsprojKeepsOnlyExactVersions(t *testing.T) {
	deps, err := parseLockFileWithErr("Api.csproj", []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="System.Text.Encodings.Web"><Version>4.5.0</Version></PackageReference>
    <PackageReference Include="Exact" Version="[1.2.3]" />
    <PackageReference Include="Prop" Version="$(PropVersion)" />
    <PackageReference Include="Floating" Version="2.*" />
    <PackageReference Include="Range" Version="[1.0,2.0)" />
    <PackageReference Include="Central" />
  </ItemGroup>
</Project>`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Exact@1.2.3", "Newtonsoft.Json@12.0.1", "System.Text.Encodings.Web@4.5.0"}
	if got := depNames(deps); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, d := range deps {
		if d.Ecosystem != "NuGet" || !d.Direct {
			t.Errorf("%+v: want NuGet, direct", d)
		}
	}
}

func TestParseNuGetLockIncludesTransitiveAndSkipsProjects(t *testing.T) {
	deps, err := parseLockFileWithErr("packages.lock.json", []byte(`{"version":1,"dependencies":{"net6.0":{
	  "Newtonsoft.Json":{"type":"Direct","requested":"[12.0.1, )","resolved":"13.0.3"},
	  "System.Drawing.Common":{"type":"Transitive","resolved":"4.7.0"},
	  "Shared.Lib":{"type":"Project"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := depNames(deps)
	if len(got) != 2 || got[0] != "Newtonsoft.Json@13.0.3" || got[1] != "System.Drawing.Common@4.7.0" {
		t.Errorf("got %v", got)
	}
}

func TestParsePackagesConfigAndCentralVersions(t *testing.T) {
	deps, err := parseLockFileWithErr("packages.config", []byte(`<?xml version="1.0"?>
<packages><package id="log4net" version="2.0.8" targetFramework="net452" /></packages>`))
	if err != nil || len(deps) != 1 || deps[0].Package != "log4net" || deps[0].Version != "2.0.8" {
		t.Errorf("packages.config: %v %v", deps, err)
	}
	deps, err = parseLockFileWithErr("Directory.Packages.props", []byte(
		`<Project><ItemGroup><PackageVersion Include="System.Net.Http" Version="4.3.0" /></ItemGroup></Project>`))
	if err != nil || len(deps) != 1 || deps[0].Package != "System.Net.Http" {
		t.Errorf("Directory.Packages.props: %v %v", deps, err)
	}
}

func TestCsprojIsIgnoredNextToNuGetLock(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) walker.FileEntry {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return walker.FileEntry{Path: p}
	}
	files := []walker.FileEntry{
		write("Worker.csproj", `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`),
		write("packages.lock.json", `{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3"}}}}`),
	}
	sc := &SCAScanner{}
	for _, f := range files {
		if !sc.Accepts(f) {
			t.Fatalf("%s not accepted", f.Path)
		}
	}
	var queried []string
	sc.client = fakeOSV(t, func(q osvQuery) osvBatchResult {
		queried = append(queried, q.Package.Ecosystem+":"+q.Package.Name+"@"+q.Version)
		return osvBatchResult{}
	}, nil)
	if _, _, err := sc.Scan(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if len(queried) != 1 || queried[0] != "NuGet:Newtonsoft.Json@13.0.3" {
		t.Errorf("queried %v, want only the locked NuGet:Newtonsoft.Json@13.0.3", queried)
	}
}
