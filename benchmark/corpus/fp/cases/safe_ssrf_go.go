// Package cases holds compilable false-positive fixtures. This file is real
// Go, not testdata, because benchmark/corpus/fp is scanned without
// include_tests and therefore also lands in `go build ./...`.
package cases

import (
	"net/http"
	"strings"
)

// SSRF family negative fixture (ZS-GO-012, ZS-GO-027, ZS-GO-036).
//
// Both requests go to a package-level constant. What is attacker-controlled
// is the request body and the HTTP method -- neither decides where the
// request goes, so neither is CWE-918.
//
// Before the rules were pinned with tainted_argument_index,
// "tainted_argument: true" was satisfied by any tainted identifier anywhere
// in the call's subtree, so both calls were reported as SSRF.
const auditEndpoint = "https://audit.internal.example.com/v1/events"

// http.Post(url, contentType, body): argument 2 is the request BODY.
// Forwarding user-supplied data to a fixed, trusted collector is the ordinary
// case, not request forgery.
func forwardAudit(r *http.Request) (*http.Response, error) {
	payload := r.FormValue("payload")
	return http.Post(auditEndpoint, "application/json", strings.NewReader(payload))
}

// http.NewRequest(method, url, body): the URL is argument 1 and it is a
// constant. Argument 0 (the verb) and argument 2 (the body) are both
// request-derived, and neither can redirect the request to another host.
func buildAuditRequest(r *http.Request) (*http.Request, error) {
	method := r.FormValue("method")
	payload := r.FormValue("payload")
	return http.NewRequest(method, auditEndpoint, strings.NewReader(payload))
}

// http.Get(url) takes only the destination, so the constant form is the only
// thing to assert here.
func auditHealth() (*http.Response, error) {
	return http.Get(auditEndpoint)
}
