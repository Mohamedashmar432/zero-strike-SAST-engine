package main

import (
	"fmt"
	"net/http"
)

func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// ZS-GO-023: the FORMAT STRING itself is attacker-controlled. The safe
	// fmt.Sprintf("hello %s", name) idiom must not fire — see clean.go.
	greeting := fmt.Sprintf("hello " + name)
	_ = greeting
}
