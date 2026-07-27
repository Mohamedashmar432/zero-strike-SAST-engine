package main

import (
	"html/template"
	"net/http"
)

// ZS-GO-041: template.JS cast of a tainted value embeds it as trusted script
func widget(r *http.Request) template.JS {
	code := r.URL.Query().Get("code")
	return template.JS(code)
}
