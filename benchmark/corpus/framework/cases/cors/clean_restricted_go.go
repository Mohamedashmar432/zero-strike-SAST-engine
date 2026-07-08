package corsfixture

import "net/http"

func cleanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
}
