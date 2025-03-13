package internal

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/acswindle/tutorial-go/database"
	"github.com/acswindle/tutorial-go/templates"
)

func VideoRoutes(ctx context.Context, queries *database.Queries) {
	// Render the upload video page
	http.HandleFunc("GET /video/upload", func(w http.ResponseWriter, r *http.Request) {
		_, err := ValidateToken(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		templates.UploadVideo().Render(r.Context(), w)
	})

	// Render the video page
	http.HandleFunc("GET /video/{id}", func(w http.ResponseWriter, r *http.Request) {
		videoId, err := strconv.ParseInt(r.PathValue("id"), 10, 32)
		if err != nil {
			http.Error(w, "videoId not set", http.StatusBadRequest)
			return
		}
		token, err := ValidateToken(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		url, err := queries.GetVideoUrl(ctx, database.GetVideoUrlParams{ID: int32(videoId), UserID: token.UserId})
		if err != nil {
			http.Error(w, "video not found", http.StatusNotFound)
			return
		}
		templates.Video(int32(videoId), url.String()).Render(r.Context(), w)
	})
	http.HandleFunc("POST /video/upload", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("POST /video/upload")
		token, err := ValidateToken(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		title, err := encrypt(token.DeriveKey, []byte(r.FormValue("title")))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = queries.InsertVideo(ctx, database.InsertVideoParams{
			UserID: token.UserId,
			Title:  title.Ciphertext,
			Nonce:  title.Nonce,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}
