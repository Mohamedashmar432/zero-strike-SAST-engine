// Package detector identifies the programming language of a source file
// using two complementary strategies: file-extension lookup (fast path)
// and shebang-line matching (fallback for extensionless or ambiguous files).
package detector

import "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

// Detector classifies source files by language.
type Detector interface {
	// Detect returns the language of the file at path whose raw bytes are
	// content. It returns core.LangUnknown when the language cannot be
	// determined.
	Detect(path string, content []byte) core.Language
}

// NewDetector returns the default Detector implementation.
func NewDetector() Detector {
	return &detector{}
}
