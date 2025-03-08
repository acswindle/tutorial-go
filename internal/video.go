package internal

import (
	"context"
	"net/http"
	"strconv"

	"github.com/acswindle/tutorial-go/database"
	"github.com/acswindle/tutorial-go/templates"
)

func VideoRoutes(ctx context.Context, queries *database.Queries) {
	// Render the video page
	http.HandleFunc("GET /video/{id}", func(w http.ResponseWriter, r *http.Request) {
		videoId, err := strconv.ParseInt(r.PathValue("id"), 10, 32)
		if err != nil {
			http.Error(w, "videoId not set", http.StatusBadRequest)
			return
		}
		userId := ValidateToken(w, r)
		if userId == 0 {
			return
		}
		url, err := queries.GetVidoeUrl(ctx, database.GetVidoeUrlParams{ID: int32(videoId), UserID: userId})
		if err != nil {
			http.Error(w, "video not found", http.StatusNotFound)
			return
		}
		if url == "" {
			http.Error(w, "video not found", http.StatusNotFound)
			return
		}
		templates.Video(int32(videoId), url).Render(r.Context(), w)
	})
}
