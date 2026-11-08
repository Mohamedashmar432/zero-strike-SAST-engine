package main

import "net/http"

func send() {
	http.Post("https://x1.interact.sh/", "text/plain", nil)
}
