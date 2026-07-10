//go:build cgo

package golang

import (
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangGo,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/go",
	})
}
