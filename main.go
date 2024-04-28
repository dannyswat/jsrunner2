package main

import (
	"jsrunner-server/config"
	"jsrunner-server/handlers"
	"jsrunner-server/security"
	"jsrunner-server/utils"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"jsrunner-server/middlewares"
)

func main() {
	if _, _, err := security.LoadECDSAKeyPair(); err != nil {
		security.GenerateECDSAKeyAndSave()
	}
	if config.DataStorePath != "" {
		utils.CreateFolderIfNotExists(config.DataStorePath)
	}
	utils.CreateFolderIfNotExists(config.DataStorePath + config.UserPath)
	utils.CreateFolderIfNotExists(config.DataStorePath + config.ScriptPath)
	utils.CreateFolderIfNotExists(config.DataStorePath + config.ScriptPath + "public/")

	router := chi.NewRouter()

	jwtContext := &middlewares.JWTContext{}
	router.Use(jwtContext.JWT)

	router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.Get("/", handlers.Index)
	router.Get("/health", handlers.Health)

	router.Get("/scripts", handlers.ListScripts)
	router.Get("/scripts/{id}", handlers.GetScript)
	router.Post("/scripts", handlers.SaveScript)
	router.Delete("/scripts/{id}", handlers.DeleteScript)

	router.Post("/auth/login", handlers.Login)
	router.Post("/auth/register", handlers.Register)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, router))
}
