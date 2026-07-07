package main

import "math/rand"

func generateToken() int {
	// ZS-GO-010: weak PRNG — math/rand.Int() is not cryptographically secure
	return rand.Int()
}
