package handlers

import (
	"bufio"
	"encoding/json"
	"jsrunner-server/config"
	"jsrunner-server/models"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

func isValidScriptId(scriptId string) bool {
	if scriptId == "" || len(scriptId) > 30 {
		return false
	}
	if matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", scriptId); !matched {
		return false

	}
	return true
}

func errorResponse(w http.ResponseWriter, r *http.Request, message string, status int) {
	render.Status(r, status)
	render.JSON(w, r, models.ErrorResponse(message))
}

func ListScripts(w http.ResponseWriter, r *http.Request) {
	userId := config.PublicUser
	authUserId := r.Context().Value("uid")
	if authUserId != nil && authUserId.(string) != "" {
		userId = authUserId.(string)
	}
	files, err := os.ReadDir(filepath.FromSlash(config.DataStorePath + config.ScriptPath + userId))
	if err != nil {
		errorResponse(w, r, "Failed to list scripts", http.StatusInternalServerError)
		return
	}
	var scriptList []ScriptMeta
	for _, file := range files {
		openedFile, err := os.Open(filepath.FromSlash(config.DataStorePath + config.ScriptPath + userId + "/" + file.Name()))
		if err != nil {
			errorResponse(w, r, "Failed to open script", http.StatusInternalServerError)
			return
		}
		scanner := bufio.NewScanner(openedFile)
		scanner.Scan()
		scriptName := scanner.Text()

		scriptList = append(scriptList, ScriptMeta{Key: strings.TrimRight(file.Name(), ".js"), Name: scriptName})
	}
	render.JSON(w, r, scriptList)
}

func GetScript(w http.ResponseWriter, r *http.Request) {
	userId := config.PublicUser
	scriptID := chi.URLParam(r, "id")
	if !isValidScriptId(scriptID) {
		errorResponse(w, r, "Invalid Script ID", http.StatusBadRequest)
		return
	}
	authUserId := r.Context().Value("uid")
	if authUserId != nil && authUserId.(string) != "" {
		userId = authUserId.(string)
	}
	openedFile, err := os.Open(filepath.FromSlash(config.DataStorePath + config.ScriptPath + userId + "/" + scriptID + ".js"))
	if err != nil {
		errorResponse(w, r, "Failed to open script", http.StatusInternalServerError)
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

func SaveScript(w http.ResponseWriter, r *http.Request) {
	userId := config.PublicUser
	authUserId := r.Context().Value("uid")
	if authUserId != nil && authUserId.(string) != "" {
		userId = authUserId.(string)
	}
	if userId == config.PublicUser {
		errorResponse(w, r, "Public user cannot save scripts", http.StatusForbidden)
		return
	}
	model := &ScriptContent{}
	if err := json.NewDecoder(r.Body).Decode(model); err != nil {
		errorResponse(w, r, "Failed to decode request", http.StatusBadRequest)
		return
	}
	if !isValidScriptId(model.Key) {
		errorResponse(w, r, "Invalid Script ID", http.StatusBadRequest)
		return
	}
	if model.Name == "" || len(model.Name) > 100 {
		errorResponse(w, r, "Invalid Script Name", http.StatusBadRequest)
		return
	}
	openedFile, err := os.Create(filepath.FromSlash(config.DataStorePath + config.ScriptPath + userId + "/" + model.Key + ".js"))
	if err != nil {
		errorResponse(w, r, "Failed to open script", http.StatusInternalServerError)
		return
	}
	openedFile.WriteString(model.Name + "\n")
	openedFile.WriteString(model.Content)
	openedFile.Close()

	render.JSON(w, r, models.SuccessResponse())
}

func DeleteScript(w http.ResponseWriter, r *http.Request) {
	userId := config.PublicUser
	scriptID := chi.URLParam(r, "id")
	if !isValidScriptId(scriptID) {
		errorResponse(w, r, "Invalid Script ID", http.StatusBadRequest)
		return
	}
	authUserId := r.Context().Value("uid")
	if authUserId != nil && authUserId.(string) != "" {
		userId = authUserId.(string)
	}
	if userId == config.PublicUser {
		errorResponse(w, r, "Public user cannot delete script", http.StatusForbidden)
		return
	}
	err := os.Remove(filepath.FromSlash(config.DataStorePath + config.ScriptPath + userId + "/" + scriptID + ".js"))
	if err != nil {
		errorResponse(w, r, "Failed to delete script", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, models.SuccessResponse())
}
