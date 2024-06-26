package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"

	"jsrunner-server/config"
	"jsrunner-server/middlewares"
	"jsrunner-server/security"
	"jsrunner-server/utils"
)

type LoginRequest struct {
	UserName string `json:"username"`
	Password string `json:"password"`
	Key      string `json:"key"`
}

type LoginToken struct {
	Token string `json:"token"`
}

type PublicKeyResponse struct {
	Key string `json:"key"`
}

func PublicKey(w http.ResponseWriter, r *http.Request) {
	_, publicKey, err := security.LoadECDSAKeyPair()
	if err != nil {
		_, publicKey, err = security.GenerateECDSAKeyAndSave()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			return
		}
	}
	ecdhKey, err := publicKey.ECDH()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, &PublicKeyResponse{
		Key: base64.StdEncoding.EncodeToString(ecdhKey.Bytes()),
	})
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
	privateKey, _, err := security.LoadECDSAKeyPair()
	if err != nil {
		privateKey, _, err = security.GenerateECDSAKeyAndSave()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			return
		}
	}
	if len(model.Key) > 0 {
		log.Println("Start decoding password")
		ecdhKey, err := privateKey.ECDH()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			return
		}
		log.Println("Get ECDH key")
		bytesPubKey, err := base64.StdEncoding.DecodeString(model.Key)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Println("Decode user key")
		remotePubKey, err := ecdh.P256().NewPublicKey(bytesPubKey)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Println("Read user key")
		sharedKey, err := ecdhKey.ECDH(remotePubKey)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Printf("Derive user key %d\n", len(sharedKey))
		aesCipher, err := aes.NewCipher(sharedKey)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Println("Init AES")
		pwdBytes, err := base64.StdEncoding.DecodeString(model.Password)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Printf("Decode password %d\n", len(pwdBytes))
		aesGcm, err := cipher.NewGCM(aesCipher)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Println("Init AES-GCM")
		nonceSize := aesGcm.NonceSize()
		log.Printf("Nonce size: %d", nonceSize)
		nonce, cipherText := pwdBytes[:nonceSize], pwdBytes[nonceSize:]
		log.Printf("%s %s", nonce, cipherText)
		plainText, err := aesGcm.Open(nil, nonce, cipherText, nil)
		log.Println("Plain text: " + string(plainText))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			return
		}
		log.Println("Decrypt password")
		model.Password = string(plainText)
	}
	log.Println("Password decoded " + model.Password)
	pwdFile, err := os.Open(filepath.FromSlash(config.DataStorePath + config.UserPath + strings.ToLower(model.UserName) + ".pwd"))
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
		middlewares.UserIdKey: strings.ToLower(model.UserName),
		"exp":                 time.Now().Add(time.Hour * 12).Unix(),
		"iat":                 time.Now().Unix(),
	})

	jwtTokenString, err := jwtToken.SignedString(privateKey)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		return
	}
	utils.CreateFolderIfNotExists(filepath.FromSlash(config.DataStorePath + config.ScriptPath + strings.ToLower(model.UserName)))

	token := &LoginToken{
		Token: jwtTokenString,
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    jwtTokenString,
		HttpOnly: true,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "user",
		Value: strings.ToLower(model.UserName),
		Path:  "/",
	})
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
	_, err := os.Stat(filepath.FromSlash(config.DataStorePath + config.UserPath + strings.ToLower(model.UserName) + ".pwd"))
	if err == nil {
		render.Status(r, http.StatusBadRequest)
		return
	}
	pwdFile, err := os.Create(filepath.FromSlash(config.DataStorePath + config.UserPath + strings.ToLower(model.UserName) + ".pwd"))
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

	utils.CreateFolderIfNotExists(filepath.FromSlash(config.DataStorePath + config.ScriptPath + strings.ToLower(model.UserName)))

	render.Status(r, http.StatusCreated)
}
