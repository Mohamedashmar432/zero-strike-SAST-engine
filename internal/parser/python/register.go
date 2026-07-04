//go:build cgo

package python

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangPython,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/python",
	})
}
