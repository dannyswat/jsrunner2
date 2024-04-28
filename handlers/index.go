package handlers

import (
	"net/http"

	"github.com/go-chi/render"
)

func Index(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "script.html")
}

func Health(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, map[string]string{"status": "ok"})
}
