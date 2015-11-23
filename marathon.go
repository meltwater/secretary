package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type MarathonAppResponse struct {
	Id, Version string
	Env         map[string]string
}

type MarathonApp struct {
	Id, Version string
	DeployKey   *[32]byte
	ServiceKey  *[32]byte
	Env         map[string]string
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
		return nil, errors.New(fmt.Sprintf("Failed to parse Marathon JSON response (%s)", err))
	}

	// Extract the deploy public key
	encodedDeployKey, ok := app.Env["DEPLOY_PUBLIC_KEY"]
	if !ok {
		return nil, errors.New("App is missing $DEPLOY_PUBLIC_KEY in the Marathon config \"env\" section")
	}

	deployKey, err := pemDecode(encodedDeployKey)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decode $DEPLOY_PUBLIC_KEY (%s)", err))
	}

	// Extract the optional service public key
	encodedServiceKey, ok := app.Env["SERVICE_PUBLIC_KEY"]
	var serviceKey *[32]byte
	if ok {
		serviceKey, err = pemDecode(encodedServiceKey)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to decode $SERVICE_PUBLIC_KEY (%s)", err))
		}
	}

	return &MarathonApp{Id: app.Id, Version: app.Version, DeployKey: deployKey, ServiceKey: serviceKey, Env: app.Env}, nil
}
