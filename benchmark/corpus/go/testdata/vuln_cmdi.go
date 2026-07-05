package main

import (
	"os"
	"os/exec"
)

func main() {
	// ZS-GO-001: command injection — cmd traces back to os.Args (untrusted input)
	cmd := os.Args[1]
	exec.Command(cmd)
}
