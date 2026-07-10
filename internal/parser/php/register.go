//go:build cgo

package php

import (
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/langreg"
)

func init() {
	langreg.Register(langreg.Entry{
		Language:   core.LangPHP,
		NewBuilder: func() ir.Builder { return NewIRBuilder() },
		RuleDir:    "data/php",
	})
}
