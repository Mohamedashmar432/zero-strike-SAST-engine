package main

import "net/http"

// ZS-GO-033: http.ServeFile with a tainted path (path traversal)
func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	http.ServeFile(w, r, name)
}
