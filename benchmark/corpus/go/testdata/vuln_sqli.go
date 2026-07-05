package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ZS-GO-002: SQL injection — query built by concatenating tainted id
	query := "SELECT * FROM users WHERE id = " + id
	db.Query(query)
}
