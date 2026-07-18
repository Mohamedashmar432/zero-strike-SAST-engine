package main

import "crypto/tls"

func newInsecureTLSConfig() *tls.Config {
	// ZS-GO-021: certificate verification disabled — struct-literal field
	return &tls.Config{InsecureSkipVerify: true}
}
