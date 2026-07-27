package main

import (
	"io/ioutil"
	"net/http"
)

// ZS-GO-035: ioutil.ReadFile with a tainted path (path traversal)
func readConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	ioutil.ReadFile(name)
}
