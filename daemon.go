package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
)

func errorResponse(w http.ResponseWriter, r *http.Request, err interface{}, statusCode int) {
	log.Printf("HTTP %d from %s: %s", statusCode, r.RemoteAddr, err)
	http.Error(w, fmt.Sprintf("%s", err), statusCode)
}

func daemonCommand(listenAddress string, marathonUrl string, configKey *[32]byte, masterKey *[32]byte) {
	http.HandleFunc("/v1/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			errorResponse(w, r, "Expected POST method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			errorResponse(w, r, "Expected application/x-www-form-urlencoded request body", http.StatusUnsupportedMediaType)
			return
		}

		appId := r.Form.Get("appid")
		appVersion := r.Form.Get("appversion")
		taskId := r.Form.Get("taskid")
		serviceEnvelope := r.Form.Get("envelope")
		log.Printf("Received request from %s (%s, %s) at %s with envelope %s", appId, taskId, appVersion, r.RemoteAddr, ellipsis(serviceEnvelope, 64))

		if appId == "" || taskId == "" || appVersion == "" || serviceEnvelope == "" {
			errorResponse(w, r, errors.New("Expected parameters {appid, appversion, taskid, envelope}"), http.StatusBadRequest)
			return
		}

		// Resolve app config version from Marathon
		app, err := getMarathonApp(marathonUrl, appId, appVersion)
		if err != nil {
			errorResponse(w, r, err, http.StatusInternalServerError)
			return
		}

		// Authenticate with public key of service and decrypt
		configEnvelope, err := decryptEnvelope(app.ServiceKey, masterKey, serviceEnvelope)
		if err != nil {
			errorResponse(w, r, err, http.StatusBadRequest)
			return
		}

		// Verify that the secret is actually part of the service's config
		found := false
		for _, value := range app.Env {
			if value == string(configEnvelope) {
				found = true
			}
		}

		if !found {
			errorResponse(w, r, errors.New("Given secret isn't part of app config (bug or hacking attempt?)"), http.StatusUnauthorized)
			return
		}

		// Authenticate with config key and decrypt
		plaintext, err := decryptEnvelope(configKey, masterKey, string(configEnvelope))
		if err != nil {
			errorResponse(w, r, err, http.StatusBadRequest)
			return
		}

		// Encrypt with public key of service
		encrypted, err := encryptEnvelope(app.ServiceKey, masterKey, plaintext)
		if err != nil {
			errorResponse(w, r, err, http.StatusInternalServerError)
			return
		}

		w.Write([]byte(encrypted))
	})

	log.Printf("Daemon listening on %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
