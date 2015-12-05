package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteCrypto(t *testing.T) {
	appsResponse, err := ioutil.ReadFile("./resources/test/marathon-apps-response.json")
	assert.Nil(t, err)

	versionsResponse, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	// Start in-test HTTP server that emulates Marathon
	marathon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/apps/demo/webapp" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponse))
		case r.URL.Path == "/v2/apps/demo/webapp/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponse))
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer marathon.Close()

	// Start secretary daemon
	handler := decryptEndpointHandler(marathon.URL,
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/config-private-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/decrypt":
			handler(w, r)
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer daemon.Close()

	// Create crypto implementation that talks to daemon
	deployPrivateKey, err := pemDecode("8Cw5ysGd14dRObahAX/MtPrkmc7tOVj6OX5lM8HxerI=")
	assert.Nil(t, err)

	crypto := newRemoteCrypto(daemon.URL, "/demo/webapp",
		"2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d",
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/master-public-key.pem"),
		deployPrivateKey,
		pemRead("./resources/test/keys/myservice-private-key.pem"))

	plaintext, err := crypto.Decrypt("ENC[NACL,9eXE3SFcX28qlijqHLUm47HbrMtIL6xJtcTLrc5Ucr3yvgRBNesFmSVFYqWqsKRlaPZUE5s124dpNOwUsMFuJpUFuPle9mi037UMReKrdXs/vSbOcRoJUWkGUxyXRywj4LS4dBlea2y9eVIYYHYHQDC4DFGaVd/2wftoGseph1pC1+026CCuzXgVphS0d5u+3gsgi5WMnLOTDVp8TQpsptW64sn/RrulWsp4Ci2O9c0Nqt+PFNlB70GZQlz7aWSQjCkBTbdCDwlwPA==]")
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext))
}
