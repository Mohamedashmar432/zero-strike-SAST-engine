package main

import "net/http"

// ZS-GO-036: http.NewRequest to a tainted URL (SSRF)
func fetchData(r *http.Request) {
	url := r.URL.Query().Get("url")
	http.NewRequest("GET", url, nil)
}
