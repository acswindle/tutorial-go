package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/acswindle/tutorial-go/templates"
	"github.com/jackc/pgx/v5"
)

func main() {
	godotenv.Load()
	dbURL, envset := os.LookupEnv("DATABASE_URL")
	if !envset {
		log.Fatal("DATABASE_FILE not set")
	}
	ctx := context.Background()
	pgx.Connect(ctx, dbURL)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		templates.Home().Render(r.Context(), w)
	})

	println("Listening on port 8080")
	http.ListenAndServe(":8080", nil)
}
