package main

import (
	"net/http"
	"os"
)

func saveHandler(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("dest")
	// ZS-GO-024: tainted destination path reaches os.WriteFile
	os.WriteFile(dest, []byte("saved"), 0644)
}
