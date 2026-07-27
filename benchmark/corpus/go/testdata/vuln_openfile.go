package main

import (
	"net/http"
	"os"
)

// ZS-GO-034: os.OpenFile with a tainted path (path traversal)
func readReport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	os.OpenFile(name, os.O_RDONLY, 0)
}
