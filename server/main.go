package main

import (
	"jsrunner-server/handlers"
	"net/http"

	"github.com/go-chi/chi/v5"

	"jsrunner-server/middlewares"
)

func main() {
	router := chi.NewRouter()

	jwtContext := &middlewares.JWTContext{}
	router.Use(jwtContext.JWT)

	router.Get("/scripts/list", func(w http.ResponseWriter, r *http.Request) {

	})

	router.Get("/scripts/{id}", func(w http.ResponseWriter, r *http.Request) {

	})

	router.Post("/auth/login", handlers.Login)
	router.Post("/auth/register", handlers.Register)
}
