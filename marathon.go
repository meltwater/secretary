package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type MarathonAppResponse struct {
	Id      string
	Version string
	Env     map[string]string
}

type MarathonApp struct {
	ServiceKey *[32]byte
	Env        map[string]string
}

func getMarathonApp(marathonUrl string, appid string, version string) (*MarathonApp, error) {
	// Check if task config is of an older version
	body, err := httpGet(fmt.Sprintf("%s/v2/apps/%s/versions/%s", marathonUrl,
		strings.Replace(strings.Replace(url.QueryEscape(appid), "..", "", -1), "%2F", "/", -1),
		url.QueryEscape(version)))
	if err != nil {
		return nil, err
	}

	var app MarathonAppResponse
	err = json.Unmarshal(body, &app)
	if err != nil || app.Id != appid || app.Version != version {
		return nil, errors.New(fmt.Sprintf("Failed to JSON parse Marathon response (%s)", err))
	}

	// Extract the service public key
	encoded, ok := app.Env["SERVICE_PUBLIC_KEY"]
	if !ok {
		return nil, errors.New("App is missing $SERVICE_PUBLIC_KEY in the Marathon config \"env\" section")
	}

	pemBlock, _ := pem.Decode([]byte(fmt.Sprintf("-----BEGIN NACL PUBLIC KEY-----\n%s\n-----END NACL PUBLIC KEY-----", encoded))) //decodeKey(encoded)
	publicKey, err := asKey(pemBlock.Bytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decode $SERVICE_PUBLIC_KEY (%s)", err))
	}

	return &MarathonApp{ServiceKey: publicKey, Env: app.Env}, nil
}
