// Negative fixture for the path-traversal rule family (ZS-GO-003/006/024/
// 033/034/035). Every filesystem path below is a compile-time constant, so
// nothing here can escape a directory. What IS request-derived is the file
// *contents* — the case that made os.WriteFile fire before the family was
// pinned to its path argument. Tainted bytes written to a fixed path are
// not CWE-22.
//
// Lives in fp/cases rather than testdata/ because the fp corpus does not
// set include_tests; it is therefore compiled by `go build ./...` and must
// stay valid, self-contained Go.
package cases

import (
	"io/ioutil"
	"net/http"
	"os"
)

const (
	auditLogPath = "/var/log/app/audit.log"
	configPath   = "config/app.yaml"
)

// appendAudit is the headline case: constant destination, tainted contents.
func appendAudit(r *http.Request) error {
	note := r.FormValue("note")
	return os.WriteFile(auditLogPath, []byte(note), 0o600)
}

// appendAuditStream is the same shape through os.OpenFile — the path is
// argument 0 and constant; the flag and mode carry no location.
func appendAuditStream(r *http.Request) error {
	note := r.FormValue("note")
	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(note)
	return err
}

func loadConfig() ([]byte, error) {
	return os.ReadFile(configPath)
}

func loadLegacyConfig() ([]byte, error) {
	return ioutil.ReadFile("config/legacy.ini")
}

func openBundle() (*os.File, error) {
	return os.Open("assets/bundle.tar")
}

// serveIndex is why http.ServeFile needed index 2 rather than "any
// argument": *http.Request is a taint source in every handler, but it is
// not the path. The served path here is a literal.
func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}
