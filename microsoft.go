package main

import (
	"AzureSecuredAPIWithOT/helpers/pages"
	"AzureSecuredAPIWithOT/logger"
	"encoding/json"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	oauthConfMs = &oauth2.Config{
		Scopes: []string{"api://bfee93bf-32a7-4793-bfe0-7e052aa5d85c/access_as_user"},
	}
	oauthStateStringMs = ""
)

func InitializeOAuthMicrosoft() {
	oauthConfMs.ClientID = viper.GetString("microsoft.clientID")
	oauthConfMs.ClientSecret = viper.GetString("microsoft.clientSecret")
	oauthConfMs.Endpoint = microsoft.AzureADEndpoint(viper.GetString("microsoft.tenant"))
	oauthStateStringMs = viper.GetString("oauthStateString")
}

func HandleMicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Host, "azure") {
		oauthConfMs.RedirectURL = "https://" + r.Host + "/callback-ms"
	} else {
		oauthConfMs.RedirectURL = "http://" + r.Host + "/callback-ms"
	}
	handleLogin(w, r, oauthConfMs, oauthStateStringMs)
}

func handleLogin(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
	URL, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		logger.Log.Error("Parse: " + err.Error())
	}
	logger.Log.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	logger.Log.Info(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

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

		tokenjson, err := json.Marshal(token)
		if err != nil {
			logger.Log.Error("Error in Marshalling the token")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(pages.CallBackHeaderPage))
		w.Write(tokenjson)
		w.Write([]byte(pages.CallBackFooterPage))

	}

}

func ProtectedRoute(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(pages.SecureArea))
}

func LogoutRoute(writer http.ResponseWriter, request *http.Request) {
	cookie := &http.Cookie{
		Name:   "access_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(writer, cookie)
	http.Redirect(writer, request, "/", http.StatusTemporaryRedirect)
}
