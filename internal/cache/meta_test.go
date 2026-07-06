package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func baseMeta() Meta {
	return Meta{FormatVersion: 1, EngineVersion: "engine-v1", RuleSetHash: "rules-v1", IRSchemaVersion: 1}
}

func TestOpen_FirstRunCreatesLayoutAndSkipsComparison(t *testing.T) {
	root := t.TempDir()

	m, err := Open(root, baseMeta())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if m == nil || m.Findings == nil || m.AST == nil {
		t.Fatalf("Open returned an incomplete Manager: %+v", m)
	}

	for _, dir := range []string{findingsDirName, irDirName} {
		if info, err := os.Stat(filepath.Join(root, dir)); err != nil || !info.IsDir() {
			t.Fatalf("expected directory %s to exist after first Open, err=%v", dir, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, metaFileName)); err != nil {
		t.Fatalf("expected meta.json to exist after first Open: %v", err)
	}
}

// seedManager populates both the findings and IR caches with one entry each,
// returning the file path / content hash used so callers can assert on them.
func seedManager(t *testing.T, m *Manager) (filePath, contentHash string) {
	t.Helper()
	filePath = "seed.py"
	contentHash = "seed-hash"

	if err := m.Findings.Set(Entry{FilePath: filePath, SHA256: contentHash}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	if err := m.AST.SetIR(filePath, contentHash, []byte("ir-payload")); err != nil {
		t.Fatalf("seed SetIR: %v", err)
	}
	return filePath, contentHash
}

func TestOpen_FormatVersionMismatchWipesEverything(t *testing.T) {
	root := t.TempDir()
	base := baseMeta()

	m1, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	fp, hash := seedManager(t, m1)

	changed := base
	changed.FormatVersion = base.FormatVersion + 1

	m2, err := Open(root, changed)
	if err != nil {
		t.Fatalf("Open (2nd): %v", err)
	}

	if _, ok := m2.Findings.Get(fp); ok {
		t.Fatal("expected findings to be wiped on a FormatVersion mismatch")
	}
	if _, ok := m2.AST.GetIR(fp, hash); ok {
		t.Fatal("expected IR to be wiped on a FormatVersion mismatch")
	}
}

func TestOpen_EngineVersionMismatchWipesFindingsAndIR(t *testing.T) {
	root := t.TempDir()
	base := baseMeta()

	m1, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	fp, hash := seedManager(t, m1)

	changed := base
	changed.EngineVersion = "engine-v2"

	m2, err := Open(root, changed)
	if err != nil {
		t.Fatalf("Open (2nd): %v", err)
	}

	if _, ok := m2.Findings.Get(fp); ok {
		t.Fatal("expected findings to be wiped on an EngineVersion mismatch")
	}
	if _, ok := m2.AST.GetIR(fp, hash); ok {
		t.Fatal("expected IR to be wiped on an EngineVersion mismatch")
	}
}

// TestOpen_RuleSetHashMismatchWipesOnlyFindings is the most important
// invalidation test: it proves the IR cache genuinely survives a rule-set
// change (parsing doesn't depend on rules), not merely that Open doesn't
// crash.
func TestOpen_RuleSetHashMismatchWipesOnlyFindings(t *testing.T) {
	root := t.TempDir()
	base := baseMeta()

	m1, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	fp, hash := seedManager(t, m1)

	changed := base
	changed.RuleSetHash = "rules-v2"

	m2, err := Open(root, changed)
	if err != nil {
		t.Fatalf("Open (2nd): %v", err)
	}

	if _, ok := m2.Findings.Get(fp); ok {
		t.Fatal("expected findings to be wiped on a RuleSetHash mismatch")
	}
	irData, ok := m2.AST.GetIR(fp, hash)
	if !ok {
		t.Fatal("expected IR to SURVIVE a RuleSetHash mismatch, but it was wiped")
	}
	if string(irData) != "ir-payload" {
		t.Fatalf("surviving IR payload = %q, want %q", irData, "ir-payload")
	}
}

// TestOpen_IRSchemaVersionMismatchWipesOnlyIR mirrors the RuleSetHash test:
// an IR schema change must not discard already-cached findings.
func TestOpen_IRSchemaVersionMismatchWipesOnlyIR(t *testing.T) {
	root := t.TempDir()
	base := baseMeta()

	m1, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	fp, hash := seedManager(t, m1)

	changed := base
	changed.IRSchemaVersion = base.IRSchemaVersion + 1

	m2, err := Open(root, changed)
	if err != nil {
		t.Fatalf("Open (2nd): %v", err)
	}

	if _, ok := m2.AST.GetIR(fp, hash); ok {
		t.Fatal("expected IR to be wiped on an IRSchemaVersion mismatch")
	}
	entry, ok := m2.Findings.Get(fp)
	if !ok {
		t.Fatal("expected findings to SURVIVE an IRSchemaVersion mismatch, but they were wiped")
	}
	if entry.SHA256 != hash {
		t.Fatalf("surviving Entry.SHA256 = %q, want %q", entry.SHA256, hash)
	}
}

func TestOpen_MatchingMetaWipesNothing(t *testing.T) {
	root := t.TempDir()
	base := baseMeta()

	m1, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	fp, hash := seedManager(t, m1)

	m2, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (2nd): %v", err)
	}

	if _, ok := m2.Findings.Get(fp); !ok {
		t.Fatal("expected findings to survive a re-Open with identical Meta")
	}
	if _, ok := m2.AST.GetIR(fp, hash); !ok {
		t.Fatal("expected IR to survive a re-Open with identical Meta")
	}
}

// TestOpen_CorruptMetaWipesEverything locks in Open's documented handling
// of a meta.json that exists but can't be parsed: treated the same as a
// FormatVersion mismatch (wipe everything), not as "no prior meta" and not
// as a hard error. Without this test, a future refactor of readPriorMeta
// could silently change corrupt-file handling to "treat as first run"
// (leaving prior, unverifiable cache data in place) without any test
// failing.
func TestOpen_CorruptMetaWipesEverything(t *testing.T) {
	root := t.TempDir()
	base := baseMeta()

	m1, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	fp, hash := seedManager(t, m1)

	// Simulate a truncated/corrupted meta.json from an out-of-band edit or
	// a crash mid-write outside this package's own atomic write path.
	metaPath := filepath.Join(root, metaFileName)
	if err := os.WriteFile(metaPath, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("corrupt meta.json: %v", err)
	}

	m2, err := Open(root, base)
	if err != nil {
		t.Fatalf("Open with corrupt meta.json returned an error, want a safe wipe-and-recover: %v", err)
	}

	if _, ok := m2.Findings.Get(fp); ok {
		t.Fatal("expected findings to be wiped when meta.json was corrupt")
	}
	if _, ok := m2.AST.GetIR(fp, hash); ok {
		t.Fatal("expected IR to be wiped when meta.json was corrupt")
	}

	// meta.json must end up valid again so a subsequent Open doesn't keep
	// re-triggering a full wipe forever.
	data, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta.json after recovery: %v", err)
	}
	var recovered Meta
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("meta.json after recovery is still not valid JSON: %v", err)
	}
	if recovered != base {
		t.Fatalf("recovered meta.json = %+v, want %+v", recovered, base)
	}
}
