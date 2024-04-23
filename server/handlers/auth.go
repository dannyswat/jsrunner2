package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"

	"jsrunner-server/security"
)

type LoginRequest struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type LoginToken struct {
	Token string `json:"token"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	model := &LoginRequest{}
	if err := json.NewDecoder(r.Body).Decode(model); err != nil {
		render.Status(r, http.StatusBadRequest)
		return
	}
	if len(model.UserName) == 0 || len(model.Password) == 0 {
		render.Status(r, http.StatusBadRequest)
		return
	}
	pwdFile, err := os.Open("users/" + strings.ToLower(model.UserName) + ".pwd")
	if err != nil {
		render.Status(r, http.StatusUnauthorized)
		return
	}
	pwdByte, err := io.ReadAll(pwdFile)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
	}

	pwdMatch, err := argon2id.ComparePasswordAndHash(model.Password, string(pwdByte))

	if err != nil || !pwdMatch {
		render.Status(r, http.StatusUnauthorized)
		return
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"uid": strings.ToLower(model.UserName),
		"exp": time.Now().Add(time.Hour * 12).Unix(),
		"iat": time.Now().Unix(),
	})
	privateKey, _, err := security.LoadECDSAKeyPair()
	if err != nil {
		privateKey, _, err = security.GenerateECDSAKeyAndSave()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			return
		}
	}
	jwtTokenString, err := jwtToken.SignedString(privateKey)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		return
	}
	if _, err := os.Stat("scripts/" + strings.ToLower(model.UserName)); err != nil {
		os.Mkdir("scripts/"+strings.ToLower(model.UserName), 0755)
	}
	token := &LoginToken{
		Token: jwtTokenString,
	}
	render.JSON(w, r, token)
}

type RegisterRequest struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	model := &RegisterRequest{}
	if err := json.NewDecoder(r.Body).Decode(model); err != nil {
		render.Status(r, http.StatusBadRequest)
		return
	}
	if len(model.UserName) == 0 || len(model.Password) == 0 || strings.ToLower(model.UserName) == "public" {
		render.Status(r, http.StatusBadRequest)
		return
	}
	_, err := os.Stat("users/" + strings.ToLower(model.UserName) + ".pwd")
	if err == nil {
		render.Status(r, http.StatusBadRequest)
		return
	}
	pwdFile, err := os.Create("users/" + strings.ToLower(model.UserName) + ".pwd")
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		return
	}
	hash, err := argon2id.CreateHash(model.Password, argon2id.DefaultParams)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		return
	}
	pwdFile.Write([]byte(hash))
	pwdFile.Close()

	if _, err := os.Stat("scripts/" + strings.ToLower(model.UserName)); err != nil {
		os.Mkdir("scripts/"+strings.ToLower(model.UserName), 0755)
	}

	render.Status(r, http.StatusCreated)
}
