package cache

import (
	"reflect"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
)

func TestDiskCache_SetGetRoundTrip(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	entry := Entry{FilePath: "a/b.py", SHA256: "deadbeef", FindingIDs: []string{"1", "2"}}
	if err := dc.Set(entry); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok := dc.Get(entry.FilePath)
	if !ok {
		t.Fatal("expected a cache hit after Set")
	}
	if !reflect.DeepEqual(got, entry) {
		t.Fatalf("Get returned %+v, want %+v", got, entry)
	}
}

func TestDiskCache_PutGetFindingsRoundTrip(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	findings := []core.Finding{
		{ID: "1", RuleID: "r1", Message: "sql injection", Severity: core.SeverityHigh},
		{ID: "2", RuleID: "r2", Message: "xss", Severity: core.SeverityMedium},
	}
	if err := dc.PutFindings("a/b.py", findings); err != nil {
		t.Fatalf("PutFindings: %v", err)
	}

	got, err := dc.GetFindings("a/b.py")
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if !reflect.DeepEqual(got, findings) {
		t.Fatalf("GetFindings returned %+v, want %+v", got, findings)
	}
}

func TestDiskCache_MissReturnsCleanZeroValues(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	entry, ok := dc.Get("does/not/exist.py")
	if ok {
		t.Fatal("expected a miss for an unknown file path")
	}
	if !reflect.DeepEqual(entry, Entry{}) {
		t.Fatalf("expected zero-value Entry on miss, got %+v", entry)
	}

	findings, err := dc.GetFindings("does/not/exist.py")
	if err != nil {
		t.Fatalf("GetFindings on miss returned an error: %v", err)
	}
	if findings != nil {
		t.Fatalf("expected nil findings on miss, got %+v", findings)
	}
}

func TestDiskCache_RemoveThenGetIsMiss(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	entry := Entry{FilePath: "x.py", SHA256: "abc123"}
	if err := dc.Set(entry); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok := dc.Get(entry.FilePath); !ok {
		t.Fatal("expected a hit before Remove")
	}

	if err := dc.Remove(entry.FilePath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := dc.Get(entry.FilePath); ok {
		t.Fatal("expected a miss after Remove")
	}

	// Removing an already-absent entry must not error.
	if err := dc.Remove(entry.FilePath); err != nil {
		t.Fatalf("Remove on an already-removed entry returned an error: %v", err)
	}
}

// TestDiskCache_SetAndPutFindingsShareOneRecord exercises the documented
// design choice that Set and PutFindings read-modify-write the same
// on-disk record: setting an Entry must not clobber Findings written
// earlier for the same path, and vice versa.
func TestDiskCache_SetAndPutFindingsShareOneRecord(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	const fp = "shared.py"
	entry := Entry{FilePath: fp, SHA256: "h1"}
	findings := []core.Finding{{ID: "1", RuleID: "r1"}}

	if err := dc.Set(entry); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := dc.PutFindings(fp, findings); err != nil {
		t.Fatalf("PutFindings: %v", err)
	}

	gotEntry, ok := dc.Get(fp)
	if !ok {
		t.Fatal("expected Entry to survive PutFindings")
	}
	if !reflect.DeepEqual(gotEntry, entry) {
		t.Fatalf("Entry after PutFindings = %+v, want %+v", gotEntry, entry)
	}

	gotFindings, err := dc.GetFindings(fp)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if !reflect.DeepEqual(gotFindings, findings) {
		t.Fatalf("Findings = %+v, want %+v", gotFindings, findings)
	}
}

func TestDiskCache_Close(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	if err := dc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
