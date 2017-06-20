package flickr

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type request struct {
	endpoint string
	client   *http.Client
	verb     string
	params   *url.Values
}

func newRequest(client *http.Client) *request {
	if client == nil {
		client = &http.Client{}
	}
	return &request{
		endpoint: APIURL,
		client:   client,
		verb:     "GET",
		params: &url.Values{
			"oauth_version":          []string{"1.0"},
			"oauth_signature_method": []string{"HMAC-SHA1"},
			"oauth_nonce":            []string{generateNonce(16)},
			"oauth_timestamp":        []string{fmt.Sprintf("%d", time.Now().Unix())},
		},
	}
}

func generateNonce(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Int63()%int64(len(letters))]
	}
	return string(b)
}

func (r *request) getURL() string {
	return fmt.Sprintf("%s?%s", r.endpoint, r.params.Encode())
}

func (r *request) getSignatureBaseString() string {
	u := url.QueryEscape(r.endpoint)
	params := strings.Replace(r.params.Encode(), "+", "%20", -1)
	params = url.QueryEscape(params)
	return fmt.Sprintf("%s&%s&%s", r.verb, u, params)
}
