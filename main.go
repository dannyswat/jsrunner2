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
	dataPath := config.GetDataStorePath()
	if dataPath != "" {
		utils.CreateFolderIfNotExists(dataPath)
	}
	utils.CreateFolderIfNotExists(dataPath + config.UserPath)
	utils.CreateFolderIfNotExists(dataPath + config.ScriptPath)
	utils.CreateFolderIfNotExists(dataPath + config.ScriptPath + "public/")

	router := chi.NewRouter()

	jwtContext := &middlewares.JWTContext{}
	router.Use(jwtContext.JWT)

	router.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			h.ServeHTTP(w, r)
		})
	})

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
		port = os.Getenv("SERVER_PORT")
	}
	if port == "" {
		port = os.Getenv("HTTP_PLATFORM_PORT")
	}
	if port == "" {
		port = "8080"
	}
	log.Default().Println("Server starting on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
