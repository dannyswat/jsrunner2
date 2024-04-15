package main

import (
	"jsrunner-server/handlers"
	"jsrunner-server/security"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"jsrunner-server/middlewares"
)

func main() {
	if _, _, err := security.LoadECDSAKeyPair(); err != nil {
		security.GenerateECDSAKeyAndSave()
	}
	if _, err := os.Stat("users"); err != nil {
		os.Mkdir("users", 0755)
	}
	if _, err := os.Stat("scripts"); err != nil {
		os.Mkdir("scripts", 0755)
	}
	if _, err := os.Stat("scripts/public"); err != nil {
		os.Mkdir("scripts/public", 0755)
	}

	router := chi.NewRouter()

	jwtContext := &middlewares.JWTContext{}
	router.Use(jwtContext.JWT)

	router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.Get("/", handlers.Index)
	router.Get("/scripts/list", handlers.List)
	router.Get("/scripts/{id}", handlers.Get)
	router.Post("/auth/login", handlers.Login)
	router.Post("/auth/register", handlers.Register)

	http.ListenAndServe(":8080", router)
}
