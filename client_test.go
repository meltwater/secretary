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

	appsResponseNoServiceKey, err := ioutil.ReadFile("./resources/test/marathon-apps-nosvckey.json")
	assert.Nil(t, err)

	versionsResponse, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	versionsResponseBadServiceKey, err := ioutil.ReadFile("./resources/test/marathon-versions-badsvckey.json")
	assert.Nil(t, err)

	versionsResponseNoServiceKey, err := ioutil.ReadFile("./resources/test/marathon-versions-nosvckey.json")
	assert.Nil(t, err)

	// Start in-test HTTP server that emulates Marathon
	marathon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/apps/demo/webapp" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponse))
		case r.URL.Path == "/v2/apps/demo/webapp2" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponseNoServiceKey))
		case r.URL.Path == "/v2/apps/demo/webapp/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponse))
		case r.URL.Path == "/v2/apps/demo/webapp/versions/2015-11-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponseBadServiceKey))
		case r.URL.Path == "/v2/apps/demo/webapp2/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponseNoServiceKey))
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

	deployPrivateKey, err := pemDecode("8Cw5ysGd14dRObahAX/MtPrkmc7tOVj6OX5lM8HxerI=")
	assert.Nil(t, err)

	appId, appVersion, taskId := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"
	badAppVersion, badTaskId := "2015-11-04T12:25:08.426Z", "demo_webapp.0f844265-9a82-11e5-94c7-6a515f434e2d"
	deployServiceKeySecret := "ENC[NACL,9eXE3SFcX28qlijqHLUm47HbrMtIL6xJtcTLrc5Ucr3yvgRBNesFmSVFYqWqsKRlaPZUE5s124dpNOwUsMFuJpUFuPle9mi037UMReKrdXs/vSbOcRoJUWkGUxyXRywj4LS4dBlea2y9eVIYYHYHQDC4DFGaVd/2wftoGseph1pC1+026CCuzXgVphS0d5u+3gsgi5WMnLOTDVp8TQpsptW64sn/RrulWsp4Ci2O9c0Nqt+PFNlB70GZQlz7aWSQjCkBTbdCDwlwPA==]"
	deployKeySecret := "ENC[NACL,5Jje+wI4faU6ilAjwkJmehY1THiRi6Lj+IcrgWuom7dn0HDM10aQdt2C4PQJLyjhZr8md0m5KVfAGi23aRFB5vKw30QCNBx4pIBHhgm0vP/W1/2DOf2KQr3Z+zPo0smoC0m54ugauBTuFpWf/QTKUuW1]"

	// Test decryption with both deploy and service keys
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test without a service key
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp2", appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(deployKeySecret)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test with a secret that's correct but not part of config
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp2", appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt("ENC[NACL,Gk0NEy/PBF/949bR/lht1nsI09wYKkY0JOIjW9NFZFG6NTasF00OSWDRA1jA9eRjSR2/0xVCMEKoTou1PGcHSOmvFJGa71GScsI04nan/ZL2c9oeAt//mavWJlOuRokq1grdc3RVk0pwpFnzdLd2gaQW]")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 401 Error: Given secret isn't part of app config (bug or hacking attempt?))", err.Error())
	}

	// Test decryption with bad deploy key
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			pemRead("./resources/test/keys/bad-private-key.pem"),
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt secret parameter using config key and deploy key (Failed to decrypt (incorrect keys?))", err.Error())
	}

	// Test decryption with bad service key
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/bad-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt secret parameter using config key and service key (Failed to decrypt (incorrect keys?))", err.Error())
	}

	// Test with a bad master key
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp", appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/bad-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(deployKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test with a bad config key
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp", appVersion, taskId,
			pemRead("./resources/test/keys/bad-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(deployKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt secret parameter using config key and deploy key (Failed to decrypt (incorrect keys?))", err.Error())
	}

	// Test with a bad service key
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, badAppVersion, badTaskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test with a appVersion and taskId mismatch
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, badTaskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 500 Error: Given appId,appVersion,taskId doesn't correspond to HTTP request params (bug or hacking attempt?))", err.Error())
	}

	// Test with a bad config public key
	handler = decryptEndpointHandler(marathon.URL,
		pemRead("./resources/test/keys/bad-public-key.pem"),
		pemRead("./resources/test/keys/config-private-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to decrypt plaintext secret, incorrect config or master key? (Failed to decrypt (incorrect keys?)))", err.Error())
	}

	// Test with a bad config private key
	handler = decryptEndpointHandler(marathon.URL,
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/bad-private-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 401 Error: Given secret isn't part of app config (bug or hacking attempt?))", err.Error())
	}

	// Test with a bad master private key
	handler = decryptEndpointHandler(marathon.URL,
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/config-private-key.pem"),
		pemRead("./resources/test/keys/bad-private-key.pem"))

	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/config-public-key.pem"),
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(deployServiceKeySecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}
}
