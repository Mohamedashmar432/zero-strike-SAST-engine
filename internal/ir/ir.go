// Package ir defines the ZeroStrike Intermediate Representation (IR).
// All language parsers produce IRFile; all rules and engines consume IRFile.
// The IR is language-agnostic — no parser internals leak past this boundary.
package ir
