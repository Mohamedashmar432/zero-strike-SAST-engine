//go:build cgo

package java

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangJava,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/java",
	})
}
