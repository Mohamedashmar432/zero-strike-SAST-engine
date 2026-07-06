package cache

import (
	"reflect"
	"testing"
)

// TestNoopCache_SatisfiesBothInterfaces is a compile-time check (it will
// fail to build, not fail at runtime, if NoopCache stops satisfying either
// interface) that a single NoopCache value can be used wherever a Cache, a
// FindingStore, or a combined Cache+FindingStore is expected - the same
// shape DiskCache provides, and the shape cache.Manager.Findings requires.
func TestNoopCache_SatisfiesBothInterfaces(t *testing.T) {
	var asCache Cache = NoopCache{}
	var asFindingStore FindingStore = NoopCache{}
	var asBoth interface {
		Cache
		FindingStore
	} = NoopCache{}

	_ = asCache
	_ = asFindingStore
	_ = asBoth
}

func TestNoopCache_Behavior(t *testing.T) {
	var nc NoopCache

	if entry, ok := nc.Get("any/path.py"); ok || !reflect.DeepEqual(entry, Entry{}) {
		t.Fatalf("Get = (%+v, %v), want (Entry{}, false)", entry, ok)
	}
	if err := nc.Set(Entry{FilePath: "any/path.py", SHA256: "abc"}); err != nil {
		t.Fatalf("Set returned an error: %v", err)
	}
	if err := nc.Remove("any/path.py"); err != nil {
		t.Fatalf("Remove returned an error: %v", err)
	}
	if err := nc.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	if err := nc.PutFindings("any/path.py", nil); err != nil {
		t.Fatalf("PutFindings returned an error: %v", err)
	}
	if findings, err := nc.GetFindings("any/path.py"); err != nil || findings != nil {
		t.Fatalf("GetFindings = (%+v, %v), want (nil, nil)", findings, err)
	}
}

func TestNoopASTCache_Behavior(t *testing.T) {
	var na NoopASTCache
	var _ ASTCache = na

	if data, ok := na.GetIR("file.py", "hash"); ok || data != nil {
		t.Fatalf("GetIR = (%v, %v), want (nil, false)", data, ok)
	}
	if err := na.SetIR("file.py", "hash", []byte("data")); err != nil {
		t.Fatalf("SetIR returned an error: %v", err)
	}
}
