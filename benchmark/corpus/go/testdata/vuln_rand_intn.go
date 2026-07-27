package main

import "math/rand"

// ZS-GO-039: math/rand is predictable - not for security tokens
func resetCode() int {
	return rand.Intn(1000000)
}
