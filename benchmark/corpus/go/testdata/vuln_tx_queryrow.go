package main

import (
	"database/sql"
	"net/http"
)

// ZS-GO-038: tx.QueryRow with a tainted, concatenated query
func getOrder(tx *sql.Tx, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT * FROM orders WHERE id = " + id
	tx.QueryRow(query)
}
