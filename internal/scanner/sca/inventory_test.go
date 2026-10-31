package sca

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// offlineScanner is an SCAScanner whose OSV endpoint refuses connections: the inventory is parsed
// before any lookup, so it must be complete whether or not the advisory query succeeds.
func offlineScanner() *SCAScanner {
	s := New("warn")
	s.client.batchURL = "http://127.0.0.1:1/"
	s.client.retryWait = time.Millisecond
	return s
}

func TestInventoryNilBeforeScan(t *testing.T) {
	if inv := New("warn").Inventory(); inv != nil {
		t.Errorf("Inventory before Scan = %v, want nil", inv)
	}
}

func TestInventoryEmptyNotNilWhenNoManifests(t *testing.T) {
	s := offlineScanner()
	if _, _, err := s.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if inv := s.Inventory(); inv == nil || len(inv) != 0 {
		t.Errorf("Inventory after an empty scan = %#v, want empty non-nil", inv)
	}
}

// The inventory is every parsed dependency, deduped per manifest, including duplicates the
// lockfiles repeat -- not only the vulnerable ones.
func TestInventoryEqualsParsedDeps(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) walker.FileEntry {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return walker.FileEntry{Path: p}
	}
	files := []walker.FileEntry{
		write("package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.21"},"node_modules/a/node_modules/lodash":{"version":"4.17.21"}}}`),
		write("requirements.txt", "requests==2.31.0\nflask==3.0.0\nrequests==2.31.0\n"),
		write("go.mod", "module m\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n"),
	}

	s := offlineScanner()
	if _, _, err := s.Scan(context.Background(), files); err != nil {
		t.Fatal(err)
	}

	var want []Dependency
	for _, f := range files {
		data, _ := os.ReadFile(f.Path)
		d, err := parseLockFileWithErr(f.Path, data)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, d...)
	}
	want = deduplicateDeps(want)
	if len(want) < 4 {
		t.Fatalf("fixture parsed only %d deps: %v", len(want), want)
	}

	got := s.Inventory()
	key := func(d []Dependency) {
		sort.Slice(d, func(i, j int) bool {
			if d[i].Manifest != d[j].Manifest {
				return d[i].Manifest < d[j].Manifest
			}
			return d[i].Package+d[i].Version < d[j].Package+d[j].Version
		})
	}
	key(got)
	key(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inventory = %v\nwant %v", got, want)
	}
	seen := map[string]bool{}
	for _, d := range got {
		k := d.Ecosystem + "|" + d.Package + "|" + d.Version + "|" + d.Manifest
		if seen[k] {
			t.Errorf("duplicate inventory entry %s", k)
		}
		seen[k] = true
	}
}
