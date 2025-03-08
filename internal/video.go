package internal

import (
	"context"
	"net/http"

	"github.com/acswindle/tutorial-go/database"
	"github.com/acswindle/tutorial-go/templates"
)

func VideoRoutes(ctx context.Context, queries *database.Queries) {
	// Render the video page
	http.HandleFunc("GET /video/{id}", func(w http.ResponseWriter, r *http.Request) {
		templates.Video().Render(r.Context(), w)
	})
}
