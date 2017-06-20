package flickr

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// LoginHandler initializes the OAuth flow.
func (c *Client) LoginHandler(w http.ResponseWriter, r *http.Request) {
	rt, err := c.GetRequestToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	u := c.GetAuthorizeURL(rt.OAuthToken, "delete")
	claims := make(jwt.MapClaims)
	claims["secret"] = rt.OAuthTokenSecret
	claims["token"] = rt.OAuthToken
	claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString(c.SigningKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "flickr",
		Value: tokenString,
	})
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// CallbackHandler handles OAuth callback GET requests, extracts the OAuth
// verifier, and gets an access token.
func (c *Client) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("flickr")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return c.SigningKey, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	claims := token.Claims.(jwt.MapClaims)
	rt := &RequestToken{
		OAuthToken:       claims["token"].(string),
		OAuthTokenSecret: claims["secret"].(string),
	}
	v := r.FormValue("oauth_verifier")
	at, err := c.GetAccessToken(rt, v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	fmt.Println(at)
	b, err := ioutil.ReadAll(r.Body)
	fmt.Fprint(w, b, err)
}
