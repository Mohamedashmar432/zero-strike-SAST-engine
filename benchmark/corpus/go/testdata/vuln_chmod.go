package main

import "os"

func relaxPermissions() {
	// ZS-GO-026: world-writable (and executable) mode on a data file
	os.Chmod("/var/data/report.txt", 0777)
}
