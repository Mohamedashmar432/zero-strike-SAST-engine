package cache

import "testing"

func TestDiskASTCache_SetGetRoundTrip(t *testing.T) {
	c, err := NewDiskASTCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskASTCache: %v", err)
	}

	data := []byte(`[{"Kind":"root"}]`)
	if err := c.SetIR("file.py", "hash1", data); err != nil {
		t.Fatalf("SetIR: %v", err)
	}

	got, ok := c.GetIR("file.py", "hash1")
	if !ok {
		t.Fatal("expected a hit after SetIR")
	}
	if string(got) != string(data) {
		t.Fatalf("GetIR returned %q, want %q", got, data)
	}
}

func TestDiskASTCache_MissOnUnknownHash(t *testing.T) {
	c, err := NewDiskASTCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskASTCache: %v", err)
	}

	if _, ok := c.GetIR("file.py", "unknown-hash"); ok {
		t.Fatal("expected a miss for an unknown content hash")
	}
}

// TestDiskASTCache_FilePathIsNotPartOfTheKey proves the content-addressing
// design point: two different filePath values sharing the same
// contentHash must retrieve the exact same cached blob.
func TestDiskASTCache_FilePathIsNotPartOfTheKey(t *testing.T) {
	c, err := NewDiskASTCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskASTCache: %v", err)
	}

	data := []byte("identical-content-payload")
	if err := c.SetIR("path/one.py", "same-hash", data); err != nil {
		t.Fatalf("SetIR: %v", err)
	}

	got, ok := c.GetIR("completely/different/path/two.py", "same-hash")
	if !ok {
		t.Fatal("expected a hit under a different filePath with the same contentHash")
	}
	if string(got) != string(data) {
		t.Fatalf("GetIR under a different filePath returned %q, want %q", got, data)
	}
}
