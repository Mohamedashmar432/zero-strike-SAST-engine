package main

import (
	"database/sql"
	"net/http"
)

func handleExec(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ZS-GO-007: SQL injection — statement built by concatenating tainted id
	stmt := "DELETE FROM users WHERE id = " + id
	db.Exec(stmt)
}
