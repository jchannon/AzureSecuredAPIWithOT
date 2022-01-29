package main

import (
	"AzureSecuredAPIWithOT/configs"
	"AzureSecuredAPIWithOT/helpers/pages"
	"AzureSecuredAPIWithOT/logger"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/mendsley/gojwk"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func main() {
	log.Default().Println("start")

	configs.InitializeViper()

	log.Default().Println(viper.ConfigFileUsed())

	logger.InitializeZapCustomLogger()

	InitializeOAuthMicrosoft()

	// Routes for the application
	http.HandleFunc("/", HandleMain)
	http.HandleFunc("/login-ms", HandleMicrosoftLogin)
	http.HandleFunc("/callback-ms", CallBackFromMicrosoft)
	http.HandleFunc("/protected-ms", middleware(ProtectedRoute))

	logger.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
}

func HandleMain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pages.IndexPage))
}

func HandleLogin(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
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

func middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := VerifyToken(r)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func ExtractToken(r *http.Request) string {
	accessCookie, err := r.Cookie("access_token")
	if err != nil {
		return ""
	}

	bearToken := accessCookie.Value //r.Header.Get("Authorization")
	//strArr := strings.Split(bearToken, " ")
	//if len(strArr) == 2 {
	//	return strArr[1]
	//}
	//return ""

	return bearToken
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)

	//provider, err := oidc.NewProvider(r.Context(), "https://login.microsoftonline.com/"+viper.GetString("microsoft.tenant")+"/v2.0")
	//if err != nil {
	//	// handle error
	//}
	//
	//var verifier = provider.Verifier(&oidc.Config{ClientID: viper.GetString("microsoft.clientid")})
	//idToken, err := verifier.Verify(r.Context(), tokenString)
	//if err != nil {
	//	// handle error
	//}

	//return idToken, err

	//keySet, err := jwk.Fetch(r.Context(), "https://login.microsoftonline.com/common/discovery/v2.0/keys")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwa.RS256.String() {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		var keys struct{ Keys []gojwk.Key }
		parseJSONFromURL("https://login.microsoftonline.com/common/discovery/v2.0/keys", &keys)
		for _, key := range keys.Keys {
			if key.Kid == kid {
				return key.DecodePublicKey()
			}
		}
		return nil, fmt.Errorf("Key not found")
		//keys, ok := keySet.LookupKeyID(kid)
		//if !ok {
		//	return nil, fmt.Errorf("key %v not found", kid)
		//}
		//var publickey interface{}
		//err = keys.Raw(&publickey)
		//if err != nil {
		//	return nil, fmt.Errorf("could not parse pubkey")
		//}
		//
		//rsa1, ok := publickey.(*rsa.PublicKey)
		//if !ok {
		//	panic(fmt.Sprintf("expected ras key, got %T", publickey))
		//}
		//
		//rsastring, err := ExportRsaPublicKeyAsPemStr(rsa1)
		//if err != nil {
		//	return nil, fmt.Errorf("could not parse pubkey")
		//}
		//
		//key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(rsastring))
		//if err != nil {
		//	return nil, fmt.Errorf("could not parse pubkey")
		//}
		//
		//return key.Decode, nil
	})

	if err != nil {
		return nil, err
	}
	return token, nil

	//token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	//	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
	//		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	//	}
	//	//return []byte(os.Getenv("ACCESS_SECRET")), nil
	//	return []byte(""), nil
	//})
	//if err != nil {
	//	return nil, err
	//}
	//return token, nil
}

func parseJSONFromURL(url string, v interface{}) {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, v)
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

//func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
//	token, err := VerifyToken(r)
//
//	if err != nil {
//		return nil, err
//	}
//	claims, ok := token.Claims.(jwt.MapClaims)
//	if ok && token.Valid {
//		accessUuid, ok := claims["access_uuid"].(string)
//		if !ok {
//			return nil, err
//		}
//		claimuserId := claims["user_id"].(string)
//
//		userId, err := strconv.Atoi(claimuserId)
//		if err != nil {
//			return nil, err
//		}
//		return &AccessDetails{
//			AccessUuid: accessUuid,
//			UserId:     int64(userId),
//		}, nil
//	}
//	return nil, err
//}

type AccessDetails struct {
	AccessUuid string
	UserId     int64
}
