package main

import (
	"net/http"

	"github.com/acswindle/tutorial-go/templates"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		templates.Home().Render(r.Context(), w)
	})

	println("Listening on port 8080")
	http.ListenAndServe(":8080", nil)
}
