package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyCrypto(t *testing.T) {
	crypto := newKeyCrypto(
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	plaintext, err := crypto.Decrypt("ENC[NACL,fB7RSmpONiUGzaHtd8URiTSKqfBhor6BsJLSQErHH9NSgLTnxNLF60YS8ZT2IQ==]")
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext))
}

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
	encryptedSecret := "ENC[NACL,jpDAHM6WZe/1C93FLHd2M916U9AQwjT3VdvzQ7JHTHc57dLXsGE+oI8wDE2Fiw==]"

	// Test decryption with both deploy and service keys
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test decryption of a multi-line block
	{
		encryptedKey := "ENC[NACL,egFSuFDkZxsmv9w7bWyZyxCBQQeykctG2H6UTiK7EHRdQI3E3NsZBP84Gqy8c5kh8BYErki6F0eqKAxd3u/QcOuMD17YgqTGiE/PMlO75yCuBzCnZNW7Y4b5Ww03v6uo1Fr/ew==]"

		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedKey)
		assert.Nil(t, err)
		assert.Equal(t, "123456789012345678901234567890123456789012345678901234567890", string(plaintext))
	}

	// Test without a service key
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp2", appVersion, taskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test with a secret that's correct but not part of config
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp2", appVersion, taskId,
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
			pemRead("./resources/test/keys/master-public-key.pem"),
			pemRead("./resources/test/keys/bad-private-key.pem"),
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test decryption with bad service key
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/bad-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test with a bad master key
	{
		crypto := newRemoteCrypto(daemon.URL,
			"/demo/webapp", appVersion, taskId,
			pemRead("./resources/test/keys/bad-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test with a bad service key
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, badAppVersion, badTaskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test with a appVersion and taskId mismatch
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, badTaskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 500 Error: Given taskId is not running (bug or hacking attempt?))", err.Error())
	}

	// Test with a bad config public key
	handler = decryptEndpointHandler(marathon.URL,
		pemRead("./resources/test/keys/bad-public-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to decrypt plaintext secret, incorrect config or master key? (Failed to decrypt (incorrect keys?)))", err.Error())
	}

	// Test with a bad master private key
	handler = decryptEndpointHandler(marathon.URL,
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/bad-private-key.pem"))
	{
		crypto := newRemoteCrypto(daemon.URL,
			appId, appVersion, taskId,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}
}
