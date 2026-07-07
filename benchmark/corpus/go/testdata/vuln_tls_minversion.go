package main

import "crypto/tls"

func insecureConfig() *tls.Config {
	// ZS-GO-009: TLS MinVersion set to SSLv3 — POODLE-vulnerable
	return &tls.Config{MinVersion: tls.VersionSSL30}
}
