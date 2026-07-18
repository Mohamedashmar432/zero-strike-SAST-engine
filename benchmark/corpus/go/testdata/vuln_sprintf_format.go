package main

import (
	"fmt"
	"net/http"
)

func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// ZS-GO-023: tainted argument reaches fmt.Sprintf
	greeting := fmt.Sprintf("hello %s", name)
	_ = greeting
}
