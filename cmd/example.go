package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/squat/flickr"
)

var rt *flickr.RequestToken
var at *flickr.AccessToken

func main() {
	apiKey := flag.String("api-key", "", "the api key for your flickr app")
	apiSecret := flag.String("api-secret", "", "the api secret for your flickr app")
	port := flag.Int("port", 5000, "the port for your flickr app")
	flag.Parse()
	c := flickr.NewClient(*apiKey, *apiSecret, fmt.Sprintf("http://127.0.0.1:%d/auth/callback", *port))
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var err error
		// Store request token somewhere, e.g. JWT, session etc.
		rt, err = c.GetRequestToken()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		http.Redirect(w, r, c.GetAuthorizeURL(rt.OAuthToken, "delete"), http.StatusSeeOther)
	})
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		var err error
		v := r.FormValue("oauth_verifier")
		// Store access token somewhere, e.g. JWT, session etc.
		at, err = c.GetAccessToken(rt, v)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(fmt.Sprintf("Token: %s", at.OAuthToken)))
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), mux))
}
