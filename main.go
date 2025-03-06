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
	// Load the .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect to the database
	dbURL, envset := os.LookupEnv("DATABASE_URL")
	if !envset {
		log.Fatal("DATABASE_FILE not set")
	}
	ctx := context.Background()
	pgx.Connect(ctx, dbURL)

	// Serve static files
	http.Handle("/static/",
		http.StripPrefix(
			"/static/",
			http.FileServer(http.Dir("./static")),
		))

	// Render the home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		templates.Home().Render(r.Context(), w)
	})

	// Render the sign up page
	http.HandleFunc("/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		templates.SignUp().Render(r.Context(), w)
	})

	// Render the login page
	http.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		templates.LogIn().Render(r.Context(), w)
	})

	// Start the server
	println("Listening on port 8080")
	http.ListenAndServe(":8080", nil)
}
