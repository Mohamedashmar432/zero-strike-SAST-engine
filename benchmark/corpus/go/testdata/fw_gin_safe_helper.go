package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

// The helper's parameter only ever receives a constant from the handler and
// the framework binds nothing to it: no finding.
func main() {
	r := gin.Default()
	r.GET("/version", func(c *gin.Context) {
		c.String(200, launch("--version"))
	})
	r.Run()
}

func launch(flag string) string {
	out, _ := exec.Command("tool", flag).Output()
	return string(out)
}
