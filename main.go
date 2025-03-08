package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/acswindle/tutorial-go/database"
	"github.com/acswindle/tutorial-go/internal"
	"github.com/acswindle/tutorial-go/templates"
	"github.com/joho/godotenv"

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
	con, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer con.Close(ctx)
	queries := database.New(con)

	// Serve static files
	http.Handle("/static/",
		http.StripPrefix(
			"/static/",
			http.FileServer(http.Dir("./static")),
		))

	// Render the home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var loggedIn bool
		_, err := r.Cookie("token")
		if err != nil {
			loggedIn = false
		} else if internal.ValidateToken(w, r) == 0 {
			loggedIn = false
			return
		} else {
			loggedIn = true
		}
		templates.Home(loggedIn).Render(r.Context(), w)
	})

	internal.SecurityRoutes(ctx, queries)
	// Start the server
	println("Listening on port 8080")
	http.ListenAndServe(":8080", nil)
}
