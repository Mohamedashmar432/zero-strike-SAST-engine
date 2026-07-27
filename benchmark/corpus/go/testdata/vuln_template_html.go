package main

import (
	"html/template"
	"net/http"
)

// ZS-GO-040: template.HTML cast of a tainted value bypasses escaping (XSS)
func profile(r *http.Request) template.HTML {
	bio := r.URL.Query().Get("bio")
	return template.HTML(bio)
}
