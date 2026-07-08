package main

import "net/http"

func serve() {
	// ZS-GO-013: plaintext HTTP server, no TLS
	http.ListenAndServe(":8080", nil)
}
