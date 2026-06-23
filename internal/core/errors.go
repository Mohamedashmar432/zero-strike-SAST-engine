package core

import "fmt"

// ErrorKind identifies the category of a ZeroStrike error.
type ErrorKind string

const (
	ErrKindParse    ErrorKind = "parse"
	ErrKindIO       ErrorKind = "io"
	ErrKindRule     ErrorKind = "rule"
	ErrKindConfig   ErrorKind = "config"
	ErrKindInternal ErrorKind = "internal"
)

// ZeroStrikeError is the typed error type for the ZeroStrike engine.
type ZeroStrikeError struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

func (e *ZeroStrikeError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("zerostrike[%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("zerostrike[%s]: %s", e.Kind, e.Message)
}

func (e *ZeroStrikeError) Unwrap() error {
	return e.Cause
}

// NewError creates a new ZeroStrikeError.
func NewError(kind ErrorKind, message string, cause error) *ZeroStrikeError {
	return &ZeroStrikeError{Kind: kind, Message: message, Cause: cause}
}
