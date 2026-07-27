package main

import "crypto/tls"

// ZS-GO-032: TLS 1.1 is deprecated (RFC 8996)
func legacyConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS11}
}
