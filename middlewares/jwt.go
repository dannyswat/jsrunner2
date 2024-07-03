package middlewares

import (
	"context"
	"crypto/ecdsa"
	"jsrunner-server/security"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

const UserIdKey = "uid"

type JWTContext struct {
	publicKey *ecdsa.PublicKey
}

func (c JWTContext) JWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Load the public key
		if c.publicKey == nil {
			log.Println("Loading public key")
			_, publicKey, err := security.LoadECDSAKeyPair()
			if err != nil {
				log.Println("Failed to load public key")
				log.Println(err)
				http.Error(w, "Failed to load public key", http.StatusInternalServerError)
				return
			}
			c.publicKey = publicKey
		}

		authHeader := r.Header.Get("Authorization")
		authCookie, _ := r.Cookie("auth")
		cookieUserId, _ := r.Cookie("user")
		jwtTokenString := ""
		if authHeader != "" {
			jwtTokenString = authHeader[7:]
		} else if cookieUserId != nil && authCookie != nil {
			jwtTokenString = authCookie.Value
		} else {
			if authCookie != nil {
				removeAuthCookie(w)
			}
			next.ServeHTTP(w, r)
			return
		}
		if jwtTokenString != "" {

			jwtToken, err := jwt.Parse(jwtTokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return c.publicKey, nil
			})
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				removeAuthCookie(w)
				return
			}
			if !jwtToken.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				removeAuthCookie(w)
				return
			}
			authUserId := jwtToken.Claims.(jwt.MapClaims)[UserIdKey].(string)
			log.Println("Authenticated:" + authUserId)

			if authUserId != cookieUserId.Value {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				removeAuthCookie(w)
				return
			}

			//lint:ignore SA1029 No collision with other packages
			userCtx := context.WithValue(r.Context(), UserIdKey, authUserId)
			next.ServeHTTP(w, r.WithContext(userCtx))
		} else {
			next.ServeHTTP(w, r)
		}

	})
}

func removeAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "auth",
		Value:  "",
		MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "user",
		Value:  "",
		MaxAge: -1,
	})
}
