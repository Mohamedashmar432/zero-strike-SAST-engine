package testdata

import "crypto/cipher"

func staticIv(block cipher.Block) {
	// ZS-GO-045: hardcoded IV passed to NewCBCEncrypter.
	_ = cipher.NewCBCEncrypter(block, []byte("0123456789012345"))
}
