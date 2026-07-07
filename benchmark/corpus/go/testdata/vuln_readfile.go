package main

import (
	"net/http"
	"os"
)

func handleReadFile(r *http.Request) {
	// ZS-GO-006: path traversal — path traces back to a query parameter
	path := r.URL.Query().Get("path")
	os.ReadFile(path)
}
