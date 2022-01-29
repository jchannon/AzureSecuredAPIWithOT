package main

import (
	"AzureSecuredAPIWithOT/configs"
	"AzureSecuredAPIWithOT/helpers/pages"
	"AzureSecuredAPIWithOT/logger"
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
	"log"
	"net/http"
)

func main() {
	configs.InitializeViper()

	logger.InitializeZapCustomLogger()

	InitializeOAuthMicrosoft()

	// Routes for the application
	http.HandleFunc("/", HandleMain)
	http.HandleFunc("/login-ms", HandleMicrosoftLogin)
	http.HandleFunc("/callback-ms", CallBackFromMicrosoft)
	http.HandleFunc("/protected-ms", middleware(ProtectedRoute))
	http.HandleFunc("/logout-ms", LogoutRoute)

	logger.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
}

func HandleMain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pages.IndexPage))
}

func middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := verifyToken(r)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(pages.UnAuthorizedPage))
			return
		}

		next(w, r)
	}
}

func extractToken(r *http.Request) string {
	accessCookie, err := r.Cookie("access_token")
	if err != nil {
		return ""
	}

	bearToken := accessCookie.Value

	return bearToken
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := extractToken(r)

	keySet, err := jwk.Fetch(r.Context(), "https://login.microsoftonline.com/common/discovery/v2.0/keys")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwa.RS256.String() {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}
		
		publickey := &rsa.PublicKey{}
		err = keys.Raw(publickey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}

		return publickey, nil
	})

	if err != nil {
		return nil, err
	}
	return token, nil
}
