package main

import "net/http"

func proxy(resp *http.Response) {
	// ZS-GO-012: SSRF — target traces back to resp.Request.URL.Query(), not "r."
	target := resp.Request.URL.Query().Get("url")
	http.Get(target)
}
