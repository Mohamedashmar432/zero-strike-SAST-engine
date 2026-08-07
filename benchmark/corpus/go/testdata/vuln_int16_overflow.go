package main

import (
	"net/http"
	"strconv"
)

func narrow(r *http.Request) int16 {
	// ZS-GO-046: request-derived value narrowed to int16 with no bounds
	// check, so anything outside -32768..32767 wraps silently.
	//
	// The multi-value assignment below is the point of this fixture: taint
	// used to be keyed on the whole "num, _" LHS text, so `num` looked clean
	// and this rule never fired. See taint.lhsNames.
	val := r.URL.Query().Get("val")
	num, _ := strconv.Atoi(val)
	return int16(num)
}
