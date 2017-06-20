package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/squat/flickr"
)

func main() {
	apiKey := flag.String("api-key", "", "the api key for your flickr app")
	apiSecret := flag.String("api-secret", "", "the api secret for your flickr app")
	callbackURL := flag.String("callback-url", "", "the callback URL for your flickr app")
	signingKey := flag.String("signing-key", "", "a secret used to sign tokens")
	flag.Parse()
	c := flickr.NewClient(*apiKey, *apiSecret, *callbackURL, []byte(*signingKey))
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", c.LoginHandler)
	mux.HandleFunc("/auth/callback", c.CallbackHandler)
	log.Fatal(http.ListenAndServe("0.0.0.0:5000", mux))
}
