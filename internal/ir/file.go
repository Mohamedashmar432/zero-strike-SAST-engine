package ir

import "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

// IRFile is the top-level IR container for a single source file.
type IRFile struct {
	Language core.Language
	Path     string
	Root     *IRNode
	// Frameworks lists the web frameworks detected in this file with high
	// confidence (internal/fwdetect). The scanner sets it before analysis;
	// it is not part of the cached IR. Empty means no framework evidence in
	// the file, and the taint pass then keeps its default parameter seeding.
	Frameworks []FrameworkHit
}

// FrameworkHit is one high-confidence framework detection: its name and the
// evidence labels that established it.
type FrameworkHit struct {
	Name     string
	Evidence []string
}
