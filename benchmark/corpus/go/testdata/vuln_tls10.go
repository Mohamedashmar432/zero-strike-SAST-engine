package main

import "crypto/tls"

// ZS-GO-031: TLS 1.0 is deprecated (RFC 8996)
func serverConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}
