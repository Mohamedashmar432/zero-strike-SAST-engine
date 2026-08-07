package testdata

import (
	"crypto/hmac"
	"crypto/md5"
)

func weakHmac(key []byte) {
	// ZS-GO-043: weak HMAC algorithm.
	_ = hmac.New(md5.New, key)
}
