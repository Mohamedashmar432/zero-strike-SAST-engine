package main

import "crypto/des"

func encrypt(key []byte) {
	// ZS-GO-008: weak crypto — DES has a 56-bit key and is trivially brute-forced
	des.NewCipher(key)
}
