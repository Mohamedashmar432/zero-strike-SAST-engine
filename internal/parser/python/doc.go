// Package python parses Python source via tree-sitter and builds ZeroStrike
// IR. All functionality requires CGo; under CGO_ENABLED=0 this package is
// importable but empty (no parser is registered with langreg).
package python
