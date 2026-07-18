package main

import "github.com/golang-jwt/jwt/v5"

func inspectClaims(raw string) {
	// ZS-GO-022: JWT decoded without signature verification
	tok, _, _ := jwt.ParseUnverified(raw, nil)
	_ = tok
}
