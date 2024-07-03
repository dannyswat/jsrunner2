package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	"jsrunner-server/models"
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
	Key       string `json:"key"`
	Timestamp string `json:"timestamp"`
}

const TimestampFormat = "20060102150405"

func decryptPassword(pwdCipherText string, publicKey string, privateKey ecdsa.PrivateKey) (string, error) {
	ecdhKey, err := privateKey.ECDH()
	if err != nil {
		return "", models.NewServerError("Failed to convert ECDH key")
	}
	bytesPubKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", models.NewUserError("Failed to decode base64 public key")
	}
	remotePubKey, err := ecdh.P256().NewPublicKey(bytesPubKey)
	if err != nil {
		return "", models.NewUserError("Invalid public key")
	}
	sharedKey, err := ecdhKey.ECDH(remotePubKey)
	if err != nil {
		return "", models.NewUserError("Failed to derive encryption key")
	}
	aesCipher, err := aes.NewCipher(sharedKey)
	if err != nil {
		return "", models.NewUserError("Failed to create AES cipher")
	}
	pwdBytes, err := base64.StdEncoding.DecodeString(pwdCipherText)
	if err != nil {
		return "", models.NewUserError("Failed to decode the base64 password")
	}
	aesGcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", models.NewUserError("Failed to create AES-GCM")
	}
	nonceSize := aesGcm.NonceSize()
	nonce, cipherText := pwdBytes[:nonceSize], pwdBytes[nonceSize:]
	plainText, err := aesGcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", models.NewUserError("Failed to decrypt the password")
	}
	return string(plainText), nil
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
		Key:       base64.StdEncoding.EncodeToString(ecdhKey.Bytes()),
		Timestamp: time.Now().UTC().Format(TimestampFormat),
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	model := &LoginRequest{}
	if err := json.NewDecoder(r.Body).Decode(model); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, models.ErrorResponse("Invalid request"))
		return
	}
	if len(model.UserName) == 0 || len(model.Password) == 0 {
		render.Status(r, http.StatusUnauthorized)
		render.JSON(w, r, models.ErrorResponse("Invalid username or password."))
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
		pwdText, err := decryptPassword(model.Password, model.Key, *privateKey)
		if err != nil {
			if errors.Is(err, &models.UserError{}) {
				render.Status(r, http.StatusBadRequest)
			} else {
				render.Status(r, http.StatusInternalServerError)
			}
			render.JSON(w, r, models.ErrorResponse(err.Error()))
			return
		}
		if len(pwdText) > len(TimestampFormat) {
			timestamp, pwdText := pwdText[:len(TimestampFormat)], pwdText[len(TimestampFormat):]
			model.Password = pwdText
			timeValue, err := time.Parse(TimestampFormat, timestamp)
			if err != nil || timeValue.Unix() < time.Now().UTC().Unix() && timeValue.Unix()+600 < time.Now().UTC().Unix() {
				render.JSON(w, r, models.ErrorResponse("Invalid timestamp"))
				return
			}
		}
	} else {
		render.JSON(w, r, models.ErrorResponse("Password must be encrypted."))
		render.Status(r, http.StatusBadRequest)
		return
	}
	pwdFile, err := os.Open(filepath.FromSlash(config.DataStorePath + config.UserPath + strings.ToLower(model.UserName) + ".pwd"))
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		return
	}
	pwdByte, err := io.ReadAll(pwdFile)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
	}

	pwdMatch, err := argon2id.ComparePasswordAndHash(model.Password, string(pwdByte))

	if err != nil || !pwdMatch {
		render.JSON(w, r, models.ErrorResponse("Invalid username or password."))
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
