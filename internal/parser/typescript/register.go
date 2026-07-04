//go:build cgo

package typescript

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangTypeScript,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/ts",
	})
}
