package main

import (
	"log"
	"os"
)

func connectDB() {
	password := os.Getenv("DB_PASSWORD")
	// ZS-GO-028: sensitive-looking variable written to the log
	log.Printf("connecting with credentials %s", password)
}
