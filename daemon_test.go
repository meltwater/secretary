package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

	response, err := httpGet(daemon.URL + "/v1/status")
	assert.Nil(t, err)

	var parsedResponse DaemonStatusResponse
	err = json.Unmarshal(response, &parsedResponse)
	assert.Nil(t, err)
	assert.Equal(t, "OK", parsedResponse.Status)
}
