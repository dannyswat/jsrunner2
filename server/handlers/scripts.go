package handlers

import (
	"bufio"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type ScriptMeta struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ScriptContent struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	Content string `json:"script"`
}

func List(w http.ResponseWriter, r *http.Request) {
	userId := "public"
	files, err := os.ReadDir("scripts/" + userId)
	if err != nil {
		http.Error(w, "Failed to list scripts", http.StatusInternalServerError)
		return
	}
	var scriptList []ScriptMeta
	for _, file := range files {
		openedFile, err := os.Open("scripts/" + userId + "/" + file.Name())
		if err != nil {
			http.Error(w, "Failed to open script", http.StatusInternalServerError)
			return
		}
		scanner := bufio.NewScanner(openedFile)
		scanner.Scan()
		scriptName := scanner.Text()

		scriptList = append(scriptList, ScriptMeta{Key: file.Name(), Name: scriptName})
	}
	render.JSON(w, r, scriptList)
}

func Get(w http.ResponseWriter, r *http.Request) {
	userId := "public"
	scriptID := chi.URLParam(r, "id")
	if scriptID == "" {
		http.Error(w, "Script ID is required", http.StatusBadRequest)
		return
	}
	openedFile, err := os.Open("scripts/" + userId + "/" + scriptID)
	if err != nil {
		http.Error(w, "Failed to open script", http.StatusInternalServerError)
		return
	}
	scanner := bufio.NewScanner(openedFile)
	scanner.Scan()

	scriptName := scanner.Text()
	contentLine := make([]string, 0)
	for scanner.Scan() {
		contentLine = append(contentLine, scanner.Text())
	}

	scriptContent := strings.Join(contentLine, "\n")

	resp := ScriptContent{Key: scriptID, Name: scriptName, Content: string(scriptContent)}
	render.JSON(w, r, resp)
}
