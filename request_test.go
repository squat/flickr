package flickr

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestGenerateNonce(t *testing.T) {
	nonces := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		n := generateNonce(16)
		ok := nonces[n]
		if ok {
			t.Errorf("test case %d: expected nonce %q to be unique", i, n)
		}
		nonces[n] = true
	}
}

func TestNewRequest(t *testing.T) {
	r := newRequest(nil)
	if r.params == nil {
		t.Errorf("expected default request to allocate 'params'")
	}
	if r.client == nil {
		t.Errorf("expected default request to allocate 'client'")
	}
	if r.verb != "GET" {
		t.Errorf("expected default request verb to be %s, got %s", "GET", r.verb)
	}
	if r.endpoint != APIURL {
		t.Errorf("expected default request endpoint to be %s, got %s", APIURL, r.endpoint)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	r = newRequest(client)
	if r.client != client {
		t.Errorf("expected request 'client' to be %v, got %v", client, r.client)
	}
}

func TestGetSignatureBaseString(t *testing.T) {
	type testCase struct {
		endpoint string
		template string
		verb     string
	}
	cases := []testCase{
		{
			endpoint: APIURL,
			template: "%s&%s&oauth_nonce%%3D%s%%26oauth_signature_method%%3DHMAC-SHA1%%26oauth_timestamp%%3D%s%%26oauth_version%%3D1.0",
			verb:     "GET",
		},
		{
			endpoint: RequestTokenURL,
			template: "%s&%s&oauth_nonce%%3D%s%%26oauth_signature_method%%3DHMAC-SHA1%%26oauth_timestamp%%3D%s%%26oauth_version%%3D1.0",
			verb:     "POST",
		},
	}
	for i, c := range cases {
		r := newRequest(nil)
		r.endpoint = c.endpoint
		r.verb = c.verb
		nonce := r.params.Get("oauth_nonce")
		timestamp := r.params.Get("oauth_timestamp")
		value := fmt.Sprintf(c.template, c.verb, url.QueryEscape(c.endpoint), nonce, timestamp)
		if r.getSignatureBaseString() != value {
			t.Errorf("test case %d: expected signature base string to be %q, got %q", i, value, r.getSignatureBaseString())
		}
	}
}
