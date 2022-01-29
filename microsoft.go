package main

import (
	"AzureSecuredAPIWithOT/logger"
	"encoding/json"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	oauthConfMs = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:3000/callback-ms",
		Scopes:       []string{"User.Read"},
	}
	oauthStateStringMs = ""
)

/*
InitializeOAuthMicrosoft Function
*/
func InitializeOAuthMicrosoft() {
	oauthConfMs.ClientID = viper.GetString("microsoft.clientID")
	oauthConfMs.ClientSecret = viper.GetString("microsoft.clientSecret")
	oauthConfMs.Endpoint = microsoft.AzureADEndpoint(viper.GetString("microsoft.tenant"))
	oauthStateStringMs = viper.GetString("oauthStateString")
}

/*
HandleMicrosoftLogin Function
*/
func HandleMicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	HandleLogin(w, r, oauthConfMs, oauthStateStringMs)
}

/*
CallBackFromMicrosoft Function
*/
func CallBackFromMicrosoft(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Callback-ms..")

	state := r.FormValue("state")
	logger.Log.Info(state)
	if state != oauthStateStringMs {
		logger.Log.Info("invalid oauth state, expected " + oauthStateStringMs + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	logger.Log.Info(code)

	if code == "" {
		logger.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {

		token, err := oauthConfMs.Exchange(oauth2.NoContext, code)
		if err != nil {
			logger.Log.Error("oauthConfMs.Exchange() failed with " + err.Error() + "\n")
			return
		}
		logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    token.AccessToken,
			Expires:  time.Now().Add(time.Hour * 24),
			HttpOnly: false,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(token)

		//logger.Log.Info("https://graph.microsoft.com/v1.0/me")
		//client := &http.Client{}
		//req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
		//req.Header.Set("Authorization", token.AccessToken)
		//resp, err := client.Do(req)
		//
		//if err != nil {
		//	logger.Log.Error("Get: " + err.Error() + "\n")
		//	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		//	return
		//}
		//
		//defer resp.Body.Close()
		//
		//response, err := ioutil.ReadAll(resp.Body)
		//if err != nil {
		//	logger.Log.Error("ReadAll: " + err.Error() + "\n")
		//	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		//	return
		//}
		//
		//logger.Log.Info("parseResponseBody: " + string(response) + "\n")
		//
		//w.Write([]byte("Hello, I'm protected\n"))
		//w.Write([]byte(string(response)))
		//return
	}

}

func ProtectedRoute(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	logger.Log.Info("https://graph.microsoft.com/v1.0/me")
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Set("Authorization", token)
	resp, err := client.Do(req)

	if err != nil {
		logger.Log.Error("Get: " + err.Error() + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Log.Error("ReadAll: " + err.Error() + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	logger.Log.Info("parseResponseBody: " + string(response) + "\n")

	w.Write([]byte("Hello, I'm protected\n"))
	w.Write([]byte(string(response)))
}

func extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}
