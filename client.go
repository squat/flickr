package flickr

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

const (
	// AccessTokenURL is the Flickr API endpoint for requesting OAuth access tokens.
	AccessTokenURL = "https://www.flickr.com/services/oauth/access_token"
	// APIURL is the Flickr API endpoint for making general API requests.
	APIURL = "https://api.flickr.com/services/rest"
	// AuthorizeURL is the Flickr OAuth authorization endpoint.
	AuthorizeURL = "https://www.flickr.com/services/oauth/authorize"
	// RequestTokenURL is the Flickr API endpoint for requesting OAuth request tokens.
	RequestTokenURL = "https://www.flickr.com/services/oauth/request_token"
	// UploadURL is the Flickr API endpoint for uploading photos.
	UploadURL = "https://up.flickr.com/services/upload/"
	letters   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// NewClient creates a new flickr client.
func NewClient(key, secret, callback string) *Client {
	return &Client{
		APIKey:    key,
		APISecret: secret,
		Callback:  callback,
		client:    &http.Client{},
	}
}

// Client is the primary type used to interact with the Flickr API.
type Client struct {
	APIKey    string
	APISecret string
	Callback  string
	client    *http.Client
}

// RequestToken represents a Flick OAuth request token.
type RequestToken struct {
	OAuthCallbackConfirmed bool
	OAuthToken             string
	OAuthTokenSecret       string
}

// Sign creates a HMAC-SHA1 signature for a request and adds it to the request parameters.
func (c *Client) Sign(r *request, tokenSecret string) {
	key := fmt.Sprintf("%s&%s", url.QueryEscape(c.APISecret), url.QueryEscape(tokenSecret))
	text := r.getSignatureBaseString()
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(text))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	// ensure we do not sign a signature.
	r.params.Del("oauth_signature")
	r.params.Set("oauth_signature", signature)
}

// SignOAuth creates a HMAC-SHA1 signature for an OAuth request and adds it to the request parameters.
func (c *Client) SignOAuth(r *request, at *AccessToken) {
	r.params.Set("oauth_token", at.OAuthToken)
	r.params.Set("oauth_consumer_key", c.APIKey)
	c.Sign(r, at.OAuthTokenSecret)
}

// GetRequestToken begins the OAuth flow by getting a request token from Flickr.
func (c *Client) GetRequestToken() (*RequestToken, error) {
	r := newRequest(c.client)
	r.endpoint = RequestTokenURL
	r.params.Set("oauth_consumer_key", c.APIKey)
	r.params.Set("oauth_callback", url.QueryEscape(c.Callback))
	// we don't have token secret at this stage, pass an empty string
	c.Sign(r, "")
	res, err := r.client.Get(r.getURL())
	if err != nil {
		return nil, fmt.Errorf("failed to make request token request: %v", err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request token response: %v", err)
	}
	return parseRequestToken(string(body))
}

func parseRequestToken(res string) (*RequestToken, error) {
	v, err := url.ParseQuery(res)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query parameters: %v", err)
	}
	p := v.Get("oauth_problem")
	if p != "" {
		return nil, fmt.Errorf("received OAuth problem: %s", p)
	}
	c, err := strconv.ParseBool(v.Get("oauth_callback_confirmed"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", "oauth_callback_confirmed", err)
	}
	rt := RequestToken{
		OAuthCallbackConfirmed: c,
		OAuthToken:             v.Get("oauth_token"),
		OAuthTokenSecret:       v.Get("oauth_token_secret"),
	}
	return &rt, nil
}

// AccessToken represents a Flick OAuth access token.
type AccessToken struct {
	OAuthToken       string
	OAuthTokenSecret string
	Fullname         string
	UserNsid         string
	Username         string
}

// GetAccessToken finishes the OAuth flow by exchanging a verifier
// for an OAuth access token from Flickr.
func (c *Client) GetAccessToken(rt *RequestToken, verifier string) (*AccessToken, error) {
	r := newRequest(c.client)
	r.endpoint = AccessTokenURL
	r.params.Set("oauth_consumer_key", c.APIKey)
	r.params.Set("oauth_token", rt.OAuthToken)
	r.params.Set("oauth_verifier", verifier)
	c.Sign(r, rt.OAuthTokenSecret)
	res, err := r.client.Get(r.getURL())
	if err != nil {
		return nil, fmt.Errorf("failed to make access token request: %v", err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read access token response: %v", err)
	}
	return parseAccessToken(string(body))
}

func parseAccessToken(res string) (*AccessToken, error) {
	v, err := url.ParseQuery(res)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query parameters: %v", err)
	}
	p := v.Get("oauth_problem")
	if p != "" {
		return nil, fmt.Errorf("received OAuth problem: %s", p)
	}
	at := AccessToken{
		OAuthToken:       v.Get("oauth_token"),
		OAuthTokenSecret: v.Get("oauth_token_secret"),
		Fullname:         v.Get("fullname"),
		UserNsid:         v.Get("usernsid"),
		Username:         v.Get("username"),
	}
	return &at, nil
}

// GetAuthorizeURL produces a new authorization URL.
func (c *Client) GetAuthorizeURL(token, permissions string) string {
	r := newRequest(c.client)
	r.endpoint = AuthorizeURL
	r.params.Set("oauth_token", token)
	r.params.Set("perms", permissions)
	return r.getURL()
}
