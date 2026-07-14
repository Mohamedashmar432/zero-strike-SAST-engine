package main

import "net/http"

func handleEcho(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	// ZS-GO-018: reflected XSS — msg written unescaped via w.Write
	w.Write([]byte(msg))
}
