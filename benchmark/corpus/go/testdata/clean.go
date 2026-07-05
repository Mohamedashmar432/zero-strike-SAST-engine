// Negative fixture: none of the ZS-GO rules should fire here.
package main

import (
	"crypto/sha256"
	"fmt"
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
}
