package main

import (
	"database/sql"
	"net/http"
)

func handleTxExec(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ZS-GO-015: SQL injection — statement built by concatenating tainted id
	stmt := "DELETE FROM users WHERE id = " + id
	tx, _ := db.Begin()
	tx.Exec(stmt)
}
