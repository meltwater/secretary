package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Marathon /v2/apps/{app_id}/tasks response struct
type MarathonTaskResponse struct {
	Id      string
	Version string
}

// Marathon /v2/apps/{app_id} response struct
type MarathonAppResponse struct {
	Id, Version string
	Tasks       []MarathonTaskResponse
}

// Marathon /v2/apps/{app_id}/versions/{version} response struct
type MarathonVersionResponse struct {
	Id, Version string
	Env         map[string]string
}

type MarathonApp struct {
	Id, Version string
	DeployKey   *[32]byte
	ServiceKey  *[32]byte
	Env         map[string]string
}

func getMarathonApp(marathonUrl string, appId string, appVersion string, taskId string) (*MarathonApp, error) {
	// Validate that given taskId is actually still running (old deploy keys shouldn't be allows to access any secrets)
	{
		body, err := httpGet(fmt.Sprintf("%s/v2/apps/%s?embed=apps.tasks", marathonUrl,
			strings.Replace(strings.Replace(url.QueryEscape(appId), "..", "", -1), "%2F", "/", -1)))
		if err != nil {
			return nil, err
		}

		var app MarathonAppResponse
		err = json.Unmarshal(body, &app)
		if err != nil || app.Id != appId {
			return nil, errors.New(fmt.Sprintf("Failed to parse Marathon JSON response (%s)", err))
		}

		isActiveTaskid := false
		for _, task := range app.Tasks {
			if task.Id == taskId {
				isActiveTaskid = true
				break
			}
		}

		if !isActiveTaskid {
			return nil, errors.New("Given appId,appVersion,taskId doesn't correspond to HTTP request params (bug or hacking attempt?)")
		}
	}

	// Fetch the exact config version for this running task
	body, err := httpGet(fmt.Sprintf("%s/v2/apps/%s/versions/%s", marathonUrl,
		strings.Replace(strings.Replace(url.QueryEscape(appId), "..", "", -1), "%2F", "/", -1),
		url.QueryEscape(appVersion)))
	if err != nil {
		return nil, err
	}

	var taskVersion MarathonVersionResponse
	err = json.Unmarshal(body, &taskVersion)
	if err != nil || taskVersion.Id != appId || taskVersion.Version != appVersion {
		return nil, errors.New(fmt.Sprintf("Failed to parse Marathon JSON response (%s)", err))
	}

	// Extract the deploy public key
	encodedDeployKey, ok := taskVersion.Env["DEPLOY_PUBLIC_KEY"]
	if !ok {
		return nil, errors.New("App is missing $DEPLOY_PUBLIC_KEY in the Marathon config \"env\" section")
	}

	deployKey, err := pemDecode(encodedDeployKey)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decode $DEPLOY_PUBLIC_KEY (%s)", err))
	}

	// Extract the optional service public key
	encodedServiceKey, ok := taskVersion.Env["SERVICE_PUBLIC_KEY"]
	var serviceKey *[32]byte
	if ok {
		serviceKey, err = pemDecode(encodedServiceKey)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to decode $SERVICE_PUBLIC_KEY (%s)", err))
		}
	}

	return &MarathonApp{Id: taskVersion.Id, Version: taskVersion.Version, DeployKey: deployKey, ServiceKey: serviceKey, Env: taskVersion.Env}, nil
}
