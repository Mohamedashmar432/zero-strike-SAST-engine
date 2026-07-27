package main

import (
	"database/sql"
	"net/http"
)

// ZS-GO-037: db.QueryRow with a tainted, concatenated query
func getUser(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + id
	db.QueryRow(query)
}
