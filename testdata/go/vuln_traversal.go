package main

import (
	"net/http"
	"os"
)

func handler(r *http.Request) {
	// ZS-GO-003: path traversal — path traces back to a form value
	path := r.FormValue("path")
	os.Open(path)
}
