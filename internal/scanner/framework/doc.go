// Package framework detects framework-level security misconfigurations
// (insecure defaults, debug mode exposure, permissive CORS) by reading
// config files directly — no tree-sitter/IR involved, same shape as
// internal/scanner/secrets.
package framework
