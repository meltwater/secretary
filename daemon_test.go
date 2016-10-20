package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meltwater/secretary/util"
	"github.com/stretchr/testify/assert"
)

func TestDaemonStatus(t *testing.T) {
	// Start secretary daemon
	handler := statusEndpointHandler()

	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status":
			handler(w, r)
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))

	defer daemon.Close()

	response, err := util.HttpGet(daemon.URL + "/v1/status")
	assert.Nil(t, err)

	var parsedResponse DaemonStatusResponse
	err = json.Unmarshal(response, &parsedResponse)
	assert.Nil(t, err)
	assert.Equal(t, "OK", parsedResponse.Status)
}

func TestTLSDaemonStatus(t *testing.T) {
	// Start secretary daemon
	handler := statusEndpointHandler()

	daemon := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status":
			handler(w, r)
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))

	cert, err := tls.LoadX509KeyPair("./resources/test/keys/tlscertfile.pem", "./resources/test/keys/tlskeyfile.pem")
	daemon.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}

	daemon.StartTLS()
	defer daemon.Close()

	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}
	response, err := client.Get(daemon.URL + "/v1/status")
	assert.Nil(t, err)

	var parsedResponse DaemonStatusResponse

	respBody, err := util.HttpReadBody(response)

	err = json.Unmarshal(respBody, &parsedResponse)
	assert.Nil(t, err)
	assert.Equal(t, "OK", parsedResponse.Status)
}
