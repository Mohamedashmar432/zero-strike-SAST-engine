package ir

import "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

// IRFile is the top-level IR container for a single source file.
type IRFile struct {
	Language core.Language
	Path     string
	Root     *IRNode
}
