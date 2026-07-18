package main

import (
	"context"
	"os"
	"os/exec"
)

func runTool() {
	bin := os.Args[1]
	ctx := context.Background()
	// ZS-GO-025: tainted program name reaches exec.CommandContext
	exec.CommandContext(ctx, bin)
}
