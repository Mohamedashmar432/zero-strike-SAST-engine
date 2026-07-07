// Negative fixture: none of the ZS-GO rules should fire here.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"os/exec"
)

func main() {
	greeting := "hello"
	fmt.Println(greeting)

	exec.Command("ls")

	h := sha256.New()
	h.Write([]byte(greeting))

	os.Open("/etc/config")

	// crypto/rand.Int() always takes 2 arguments — must NOT match
	// ZS-GO-010's argument_count: 0 filter, which is scoped to the
	// zero-arg math/rand.Int() form only.
	rand.Int(rand.Reader, big.NewInt(100))
}
