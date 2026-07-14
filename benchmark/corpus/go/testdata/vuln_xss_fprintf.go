package main

import (
	"fmt"
	"net/http"
)

func handleGreet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ZS-GO-017: reflected XSS — name written unescaped via fmt.Fprintf
	fmt.Fprintf(w, "Hello, %s", name)
}
