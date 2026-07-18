package main

import "net/http"

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("endpoint")
	// ZS-GO-027: tainted URL reaches http.Post
	http.Post(target, "application/json", nil)
}
