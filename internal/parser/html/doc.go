// Package html parses HTML documents into the ZeroStrike IR for markup-level
// security rules (OWASP-aligned checks on tags and attributes) and extracts
// inline <script> bodies so the JavaScript rule pack can scan embedded code.
//
// HTML has no calls or assignments, so the builder models each element as a
// call IR node: the tag name becomes the callee and every attribute becomes a
// keyword-argument child (kwarg_name/kwarg_value). This lets the existing
// engine kwarg/not filters express HTML rules with no engine-specific HTML
// logic. Elements are emitted flat (not nested) so an element's attribute
// filters never bleed into a descendant element's attributes.
package html
