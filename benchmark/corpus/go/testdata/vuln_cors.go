package main

import "net/http"

func handleCors(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Query().Get("origin")
	// ZS-GO-020: CORS misconfiguration — tainted origin reflected into Access-Control-Allow-Origin
	w.Header().Set("Access-Control-Allow-Origin", origin)
}
