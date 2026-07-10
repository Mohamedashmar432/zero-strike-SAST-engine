//go:build cgo

package csharp

import (
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangCSharp,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/csharp",
	})
}
