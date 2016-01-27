package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// DaemonRequest TODO
type DaemonRequest struct {
	AppID, AppVersion, TaskID string

	// Secret encrypted with master key
	RequestedSecret string
}

// DaemonResponse TODO
type DaemonResponse struct {
	PlaintextSecret string
}

func errorResponse(w http.ResponseWriter, r *http.Request, err interface{}, statusCode int) {
	log.Printf("HTTP %d from %s: %s", statusCode, r.RemoteAddr, err)
	http.Error(w, fmt.Sprintf("%s", err), statusCode)
}

func decryptRequest(app *MarathonApp, masterKey *[32]byte, serviceEnvelope string) (*DaemonRequest, error) {
	// Authenticate with deploy key and decrypt
	body, err := decryptEnvelope(app.DeployKey, masterKey, serviceEnvelope)
	if err != nil {
		return nil, fmt.Errorf("Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (%s))", err)
	}

	// Authenticate with optional service key and decrypt
	if app.ServiceKey != nil {
		body, err = decryptEnvelope(app.ServiceKey, masterKey, string(body))
		if err != nil {
			return nil, fmt.Errorf("Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (%s))", err)
		}
	}

	// Unpack request struct
	var request DaemonRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse JSON request (%s)", err)
	}

	// Validate that appId, appVersion, taskId corresponds to HTTP request params
	if request.AppID != app.ID || request.AppVersion != app.Version || request.TaskID != app.TaskID {
		return nil, errors.New("Given appid,appversion,taskid doesn't correspond to HTTP request params (bug or hacking attempt?)")
	}

	return &request, nil
}

func verifyAuthorization(app *MarathonApp, request *DaemonRequest) (bool, error) {
	// Verify that encrypted string is present in app config
	for _, value := range app.Env {
		if strings.Contains(stripWhitespace(value), request.RequestedSecret) {
			return true, nil
		}
	}

	return false, errors.New("Given secret isn't part of app config (bug or hacking attempt?)")
}

func encryptResponse(app *MarathonApp, masterKey *[32]byte, plaintext []byte) ([]byte, error) {
	message := DaemonResponse{PlaintextSecret: encode(plaintext)}
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	// Encrypt with service key
	response := string(encoded)
	if app.ServiceKey != nil {
		response, err = encryptEnvelope(app.ServiceKey, masterKey, []byte(response))
		if err != nil {
			return nil, err
		}
	}

	// Encrypt with deploy key
	encrypted, err := encryptEnvelope(app.DeployKey, masterKey, []byte(response))
	if err != nil {
		return nil, err
	}

	return []byte(encrypted), nil
}

func decryptEndpointHandler(marathonURL string, configPublicKey *[32]byte, masterKey *[32]byte) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			errorResponse(w, r, "Expected POST method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			errorResponse(w, r, "Expected application/x-www-form-urlencoded request body", http.StatusUnsupportedMediaType)
			return
		}

		appID := r.Form.Get("appid")
		appVersion := r.Form.Get("appversion")
		taskID := r.Form.Get("taskid")
		serviceEnvelope := r.Form.Get("envelope")
		log.Printf("Received request from %s (%s, %s) at %s with envelope %s", appID, taskID, appVersion, r.RemoteAddr, ellipsis(serviceEnvelope, 64))

		if appID == "" || taskID == "" || appVersion == "" || serviceEnvelope == "" {
			errorResponse(w, r, errors.New("Expected parameters {appid, appversion, taskid, envelope}"), http.StatusBadRequest)
			return
		}

		// Resolve app config version from Marathon
		app, err := getMarathonApp(marathonURL, appID, appVersion, taskID)
		if err != nil {
			errorResponse(w, r, err, http.StatusInternalServerError)
			return
		}

		// Authenticate and decrypt request
		request, err := decryptRequest(app, masterKey, serviceEnvelope)
		if err != nil {
			errorResponse(w, r, err, http.StatusBadRequest)
			return
		}

		// Verify that the secret is actually part of the service's config
		ok, err := verifyAuthorization(app, request)
		if !ok || err != nil {
			errorResponse(w, r, err, http.StatusUnauthorized)
			return
		}

		// Authenticate with config key and decrypt secret
		plaintext, err := decryptEnvelope(configPublicKey, masterKey, request.RequestedSecret)
		if err != nil {
			errorResponse(w, r, fmt.Errorf("Failed to decrypt plaintext secret, incorrect config or master key? (%s)", err), http.StatusBadRequest)
			return
		}

		encrypted, err := encryptResponse(app, masterKey, plaintext)
		if err != nil {
			errorResponse(w, r, err, http.StatusInternalServerError)
			return
		}

		w.Write([]byte(encrypted))
	}
}

func daemonCommand(listenAddress string, marathonURL string, configPublicKey *[32]byte, masterKey *[32]byte) {
	http.HandleFunc("/v1/decrypt", decryptEndpointHandler(marathonURL, configPublicKey, masterKey))
	log.Printf("Daemon listening on %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
