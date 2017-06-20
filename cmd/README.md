# example app

This example app demonstrates how to initialize a flickr client, take a user through the OAuth flow, and make requests to the API.

## Getting Started

This example application requires a set of valid Flickr API credentials.
In order to obtain credentials, [register an app with Flickr](https://www.flickr.com/services/apps/create/).

## Running the app

The example application expects four flags:
* `--api-key`: the API key provided by Flickr
* `--api-secret`: the API secret provided by Flickr
* `--callback-url`: the OAuth callback URL for this app; this example expects `http://localhost:5000/auth/callback`
* `--signing-key`: a key to sign JWTs, e.g. `keyboardcat`

Start the app like so:
```go
go run cmd/example.go --api-key=<flickr-key> --api-secret=<flickr-secret> --callback-url=http://localhost:5000/auth/callback --signing-key=keyboardcat
```

Navigate a browser to `http://localhost:5000/auth/login` to login and test the example app.
