package middlewares

import (
	"context"
	"crypto/ecdsa"
	"jsrunner-server/security"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

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
		if authHeader != "" {
			jwtTokenString := authHeader[7:]
			jwtToken, err := jwt.Parse(jwtTokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return c.publicKey, nil
			})
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			if !jwtToken.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			userCtx := context.WithValue(r.Context(), "uid", jwtToken.Claims.(jwt.MapClaims)["uid"])
			next.ServeHTTP(w, r.WithContext(userCtx))
		} else {
			next.ServeHTTP(w, r)
		}

	})
}
