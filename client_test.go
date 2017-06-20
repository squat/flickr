package flickr

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("", "", "", []byte{})
	if c.client == nil {
		t.Errorf("expected default request to allocate 'client'")
	}
	c = NewClient("key", "secret", "callback", []byte("signing key"))
	if c.APIKey != "key" {
		t.Errorf("expected client key to be %q, got %q", "key", c.APIKey)
	}
	if c.APISecret != "secret" {
		t.Errorf("expected client secret to be %q, got %q", "secret", c.APISecret)
	}
	if c.Callback != "callback" {
		t.Errorf("expected client callback to be %q, got %q", "callback", c.Callback)
	}
	if string(c.SigningKey) != "signing key" {
		t.Errorf("expected client signing key to be %q, got %q", "signing key", string(c.SigningKey))
	}
}

func TestParseRequestToken(t *testing.T) {
	type testCase struct {
		confirmed string
		problem   string
		secret    string
		token     string
		err       error
	}
	cases := []testCase{
		{
			confirmed: "true",
			secret:    "secret",
			token:     "token",
			err:       nil,
		},
		{
			problem: "foo",
			err:     errors.New("problem: foo"),
		},
		{
			confirmed: "bar",
			err:       errors.New("strconv.ParseBool: parsing"),
		},
		{
			confirmed: "%",
			err:       errors.New("failed to parse query parameters"),
		},
	}
	for i, c := range cases {
		rt, err := parseRequestToken(fmt.Sprintf("oauth_callback_confirmed=%s&oauth_problem=%s&oauth_token_secret=%s&oauth_token=%s", c.confirmed, c.problem, c.secret, c.token))
		if c.err == nil {
			if err != nil {
				t.Errorf("test case %d: expected no error, got %v", i, err)
			}
			if strconv.FormatBool(rt.OAuthCallbackConfirmed) != c.confirmed {
				t.Errorf("test case %d: expected request token callback confirmed to be %s, got %t", i, c.confirmed, rt.OAuthCallbackConfirmed)
			}
			if rt.OAuthTokenSecret != c.secret {
				t.Errorf("test case %d: expected request token secret to be %q, got %q", i, c.secret, rt.OAuthTokenSecret)
			}
			if rt.OAuthToken != c.token {
				t.Errorf("test case %d: expected request token to be %q, got %q", i, c.token, rt.OAuthToken)
			}
		} else {
			if err == nil {
				t.Errorf("test case %d: expected error, got nothing", i)
			}
			if !strings.Contains(err.Error(), c.err.Error()) {
				t.Errorf("test case %d: expected error to contain %q, got %v", i, c.err, err)
			}
		}
	}
}

func TestParseAccessToken(t *testing.T) {
	type testCase struct {
		fullname string
		problem  string
		secret   string
		token    string
		username string
		usernsid string
		err      error
	}
	cases := []testCase{
		{
			fullname: "fullname",
			secret:   "secret",
			token:    "token",
			username: "username",
			usernsid: "usernsid",
			err:      nil,
		},
		{
			problem: "foo",
			err:     errors.New("problem: foo"),
		},
		{
			token: "%",
			err:   errors.New("failed to parse query parameters"),
		},
	}
	for i, c := range cases {
		at, err := parseAccessToken(fmt.Sprintf("fullname=%s&oauth_problem=%s&oauth_token_secret=%s&oauth_token=%s&username=%s&usernsid=%s", c.fullname, c.problem, c.secret, c.token, c.username, c.usernsid))
		if c.err == nil {
			if err != nil {
				t.Errorf("test case %d: expected no error, got %v", i, err)
			}
			if at.Fullname != c.fullname {
				t.Errorf("test case %d: expected access token fullname to be %s, got %s", i, c.fullname, at.Fullname)
			}
			if at.OAuthTokenSecret != c.secret {
				t.Errorf("test case %d: expected access token token secret to be %s, got %s", i, c.secret, at.OAuthTokenSecret)
			}
			if at.OAuthToken != c.token {
				t.Errorf("test case %d: expected access token to be %s, got %s", i, c.token, at.OAuthToken)
			}
			if at.Username != c.username {
				t.Errorf("test case %d: expected access token username to be %s, got %s", i, c.username, at.UserNsid)
			}
			if at.UserNsid != c.usernsid {
				t.Errorf("test case %d: expected access token usernsid to be %s, got %s", i, c.usernsid, at.UserNsid)
			}
		} else {
			if err == nil {
				t.Errorf("test case %d: expected error, got nothing", i)
			}
			if !strings.Contains(err.Error(), c.err.Error()) {
				t.Errorf("test case %d: expected error to contain %q, got %v", i, c.err, err)
			}
		}
	}
}

func TestGetAuthorizeURL(t *testing.T) {
	c := &Client{
		client: &http.Client{},
	}
	u := c.GetAuthorizeURL("token", "permissions")
	if !strings.Contains(u, AuthorizeURL) {
		t.Errorf("expected authorize url to contain %q, got %q", AuthorizeURL, u)
	}
	if !strings.Contains(u, "perms=permissions") {
		t.Errorf("expected authorize url to contain %q, got %q", "perms=permissions", u)
	}
	if !strings.Contains(u, "oauth_token=token") {
		t.Errorf("expected authorize url to contain %q, got %q", "oauth_token=token", u)
	}
}
