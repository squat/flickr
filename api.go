package flickr

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"path/filepath"
)

// Result is the base type for all API responses.
type Result struct {
	XMLName xml.Name `xml:"rsp"`
	Status  string   `xml:"stat,attr"`
	Error   *struct {
		Code    int    `xml:"code,attr"`
		Message string `xml:"msg,attr"`
	} `xml:"err"`
}

// parseResult unmarshals a Flickr response body into the provided interface.
func parseResult(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	err = xml.Unmarshal(body, v)
	if err != nil {
		return fmt.Errorf("failed to unmarshal body: %v", err)
	}
	return nil
}

// UploadResult is the response types for photo uploads.
type UploadResult struct {
	Result
	ID string `xml:"photoid"`
}

// Upload POSTs the photo bytes from the provided reader to Flickr.
func (c *Client) Upload(re io.Reader, name string, at *AccessToken) (*UploadResult, error) {
	r := newRequest()
	r.endpoint = UploadURL
	r.verb = "POST"
	c.SignOAuth(r, at)

	ec := make(chan error, 1)
	readBody, writeBody := io.Pipe()
	defer readBody.Close()
	writer := multipart.NewWriter(writeBody)
	go func() {
		defer writeBody.Close()
		part, err := writer.CreateFormFile("photo", filepath.Base(name))
		if err != nil {
			ec <- fmt.Errorf("failed to create multipart form: %v", err)
			return
		}
		_, err = io.Copy(part, re)
		if err != nil {
			ec <- fmt.Errorf("failed to copy data to multipart form: %v", err)
			return
		}
		for key, val := range *r.params {
			_ = writer.WriteField(key, val[0])
		}
		ec <- writer.Close()
	}()

	req, err := http.NewRequest("POST", r.endpoint, readBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request to upload URL: %v", err)
	}
	req.Header.Set("content-type", writer.FormDataContentType())
	req.ContentLength = -1
	client := new(http.Client)
	*client = *c.client
	client.Transport = &http.Transport{
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to upload URL: %v", err)
	}
	err = <-ec
	if err != nil {
		return nil, err
	}
	ur := &UploadResult{}
	err = parseResult(resp, ur)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upload result: %v", err)
	}
	return ur, nil
}
