package core

import "fmt"

// Location describes a source position within a file.
type Location struct {
	File      string
	StartLine int
	EndLine   int
	StartCol  int
	EndCol    int
}

// String returns a human-readable location string.
func (l Location) String() string {
	return fmt.Sprintf("%s:%d:%d", l.File, l.StartLine, l.StartCol)
}

// IsZero reports whether the location is unset.
func (l Location) IsZero() bool {
	return l.File == "" && l.StartLine == 0
}
