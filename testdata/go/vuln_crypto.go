package main

import "crypto/md5"

func hash(data []byte) [16]byte {
	// ZS-GO-004: weak crypto — MD5 is not safe for security-sensitive hashing
	h := md5.New()
	h.Write(data)
	return md5.Sum(data)
}
