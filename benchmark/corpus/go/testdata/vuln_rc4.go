package main

import "crypto/rc4"

func encrypt(key []byte) {
	// ZS-GO-011: weak crypto — RC4 is broken and should not be used
	rc4.NewCipher(key)
}
