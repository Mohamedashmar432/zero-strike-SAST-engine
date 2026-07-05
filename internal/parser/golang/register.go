//go:build cgo

package golang

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangGo,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/go",
	})
}
