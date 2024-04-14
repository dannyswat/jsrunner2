package handlers

import (
	"bufio"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/render"
)

type ScriptMeta struct {
	Name     string `json:"name"`
	FileName string `json:"filename"`
}

func List(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir("scripts")
	if err != nil {
		http.Error(w, "Failed to list scripts", http.StatusInternalServerError)
		return
	}
	var scriptList []ScriptMeta
	for _, file := range files {
		openedFile, err := os.Open("scripts/" + file.Name())
		if err != nil {
			http.Error(w, "Failed to open script", http.StatusInternalServerError)
			return
		}
		scriptName, err := bufio.NewReader(openedFile).ReadString('\n')
		if err != nil {
			http.Error(w, "Failed to read script", http.StatusInternalServerError)
			return
		}
		scriptList = append(scriptList, ScriptMeta{FileName: file.Name(), Name: scriptName})
	}
	render.JSON(w, r, scriptList)
}

func Get(w http.ResponseWriter, r *http.Request) {
	scriptID := r.URL.Query().Get("id")
	if scriptID == "" {
		http.Error(w, "Script ID is required", http.StatusBadRequest)
		return
	}
	openedFile, err := os.Open("scripts/" + scriptID)
	if err != nil {
		http.Error(w, "Failed to open script", http.StatusInternalServerError)
		return
	}
	scriptContent, err := io.ReadAll(openedFile)
	if err != nil {
		http.Error(w, "Failed to read script", http.StatusInternalServerError)
		return
	}
	render.PlainText(w, r, string(scriptContent))
}
