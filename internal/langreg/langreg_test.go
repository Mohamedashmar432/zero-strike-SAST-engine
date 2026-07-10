package langreg_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/langreg"
)

type fakeBuilder struct{}

func (fakeBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	return &ir.IRFile{Path: path}, nil, nil
}

func TestRegisterGetAll(t *testing.T) {
	if _, ok := langreg.Get(core.Language("zz-fake")); ok {
		t.Fatal("expected zz-fake to be unregistered")
	}

	langreg.Register(langreg.Entry{
		Language:   core.Language("zz-fake"),
		NewBuilder: func() ir.Builder { return fakeBuilder{} },
		RuleDir:    "data/zz-fake",
	})
	langreg.Register(langreg.Entry{
		Language:   core.Language("aa-fake"),
		NewBuilder: func() ir.Builder { return fakeBuilder{} },
		RuleDir:    "data/aa-fake",
	})

	e, ok := langreg.Get(core.Language("zz-fake"))
	if !ok {
		t.Fatal("expected zz-fake to be registered")
	}
	if e.RuleDir != "data/zz-fake" {
		t.Errorf("RuleDir: got %q", e.RuleDir)
	}
	f, _, err := e.NewBuilder().Build("x.zz", nil)
	if err != nil || f == nil || f.Path != "x.zz" {
		t.Errorf("NewBuilder().Build: got %v, %v", f, err)
	}

	all := langreg.All()
	if len(all) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Language >= all[i].Language {
			t.Errorf("All() not in stable language order: %v before %v", all[i-1].Language, all[i].Language)
		}
	}
}
