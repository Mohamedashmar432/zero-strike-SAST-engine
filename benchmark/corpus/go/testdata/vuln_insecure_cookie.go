package main

import "net/http"

func setAuthCookie(w http.ResponseWriter, token string) {
	// ZS-GO-016: insecure cookie — Secure/HttpOnly never set
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: token})
}
