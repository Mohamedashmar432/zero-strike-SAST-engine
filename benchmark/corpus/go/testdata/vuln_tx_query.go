package main

import (
	"database/sql"
	"net/http"
)

func handleTxQuery(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ZS-GO-014: SQL injection — query built by concatenating tainted id
	query := "SELECT * FROM users WHERE id = " + id
	tx, _ := db.Begin()
	tx.Query(query)
}
