package main

import "net/http"

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("dest")
	// ZS-GO-019: open redirect — dest is user-controlled
	http.Redirect(w, r, dest, http.StatusFound)
}
