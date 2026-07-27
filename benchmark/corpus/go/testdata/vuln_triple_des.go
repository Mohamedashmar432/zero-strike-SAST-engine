package main

import "crypto/des"

// ZS-GO-030: 3DES is deprecated (Sweet32, NIST withdrawal)
func encryptLegacy(key []byte) {
	des.NewTripleDESCipher(key)
}
