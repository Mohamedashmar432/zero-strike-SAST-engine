package main

import "crypto/sha1"

// ZS-GO-029: SHA-1 is broken for collision resistance
func digest(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}
