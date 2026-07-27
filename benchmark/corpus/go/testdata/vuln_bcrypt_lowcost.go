package main

import "golang.org/x/crypto/bcrypt"

// ZS-GO-042: bcrypt cost factor below the recommended minimum of 10
func hashPassword(pw []byte) {
	bcrypt.GenerateFromPassword(pw, 8)
}
