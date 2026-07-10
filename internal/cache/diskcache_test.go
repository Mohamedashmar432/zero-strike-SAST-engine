package cache

import (
	"reflect"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
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

// TestDiskCache_SetWithoutFollowingPutFindingsLeavesStaleFindings documents
// the known inconsistency window that Set/PutFindings called independently
// (rather than via PutRecord) can produce: a Set for a new content hash
// does not clear Findings left over from a prior, different content hash,
// because Set only touches the Entry half of the shared record. This is the
// exact scenario PutRecord (see the test below) exists to avoid — this test
// exists to keep Set/PutFindings' documented limitation from silently
// regressing (e.g. if a future change made Set clear Findings, this test
// would need to change deliberately, not by accident).
func TestDiskCache_SetWithoutFollowingPutFindingsLeavesStaleFindings(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	const fp = "drifting.py"
	staleFindings := []core.Finding{{ID: "1", RuleID: "stale-rule"}}

	// First successful scan: Entry + Findings written together.
	if err := dc.Set(Entry{FilePath: fp, SHA256: "h1"}); err != nil {
		t.Fatalf("Set (h1): %v", err)
	}
	if err := dc.PutFindings(fp, staleFindings); err != nil {
		t.Fatalf("PutFindings (h1): %v", err)
	}

	// File content changes to h2; caller calls Set for the new hash but
	// crashes/never calls PutFindings for h2's real findings.
	if err := dc.Set(Entry{FilePath: fp, SHA256: "h2"}); err != nil {
		t.Fatalf("Set (h2): %v", err)
	}

	gotEntry, ok := dc.Get(fp)
	if !ok || gotEntry.SHA256 != "h2" {
		t.Fatalf("Get after Set(h2) = %+v (ok=%v), want SHA256=h2", gotEntry, ok)
	}
	gotFindings, err := dc.GetFindings(fp)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	// This is the documented failure mode: a hash that matches h2, paired
	// with findings that were only ever produced for h1's content. A caller
	// must use PutRecord to avoid ever observing this combination.
	if !reflect.DeepEqual(gotFindings, staleFindings) {
		t.Fatalf("expected stale h1 findings to survive an unrelated Set(h2), got %+v", gotFindings)
	}
}

// TestDiskCache_PutRecordIsAtomicAndConsistent verifies PutRecord's whole
// point: an Entry and its Findings always arrive/leave together, so the
// stale-pairing window above cannot occur through PutRecord.
func TestDiskCache_PutRecordIsAtomicAndConsistent(t *testing.T) {
	dc, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	const fp = "atomic.py"
	entry1 := Entry{FilePath: fp, SHA256: "h1"}
	findings1 := []core.Finding{{ID: "1", RuleID: "r1"}}
	if err := dc.PutRecord(entry1, findings1); err != nil {
		t.Fatalf("PutRecord (h1): %v", err)
	}

	gotEntry, ok := dc.Get(fp)
	if !ok || !reflect.DeepEqual(gotEntry, entry1) {
		t.Fatalf("Get after first PutRecord = %+v (ok=%v), want %+v", gotEntry, ok, entry1)
	}
	gotFindings, err := dc.GetFindings(fp)
	if err != nil || !reflect.DeepEqual(gotFindings, findings1) {
		t.Fatalf("GetFindings after first PutRecord = %+v (err=%v), want %+v", gotFindings, err, findings1)
	}

	// A second PutRecord for a new content hash must replace BOTH halves
	// together — no window where the new Entry pairs with the old Findings.
	entry2 := Entry{FilePath: fp, SHA256: "h2"}
	findings2 := []core.Finding{{ID: "2", RuleID: "r2"}}
	if err := dc.PutRecord(entry2, findings2); err != nil {
		t.Fatalf("PutRecord (h2): %v", err)
	}

	gotEntry, ok = dc.Get(fp)
	if !ok || !reflect.DeepEqual(gotEntry, entry2) {
		t.Fatalf("Get after second PutRecord = %+v (ok=%v), want %+v", gotEntry, ok, entry2)
	}
	gotFindings, err = dc.GetFindings(fp)
	if err != nil || !reflect.DeepEqual(gotFindings, findings2) {
		t.Fatalf("GetFindings after second PutRecord = %+v (err=%v), want %+v — must not still be h1's findings", gotFindings, err, findings2)
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
