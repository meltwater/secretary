package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MarathonTaskResponse is the /v2/apps/{app_id}/tasks response struct
type MarathonTaskResponse struct {
	ID      string
	Version string
}

// MarathonAppResponse is the /v2/apps/{app_id} response struct
type MarathonAppResponse struct {
	ID, Version string
	Tasks       []MarathonTaskResponse
}

// MarathonAppsResponse is wrapping MarathonAppResponse
type MarathonAppsResponse struct {
	App MarathonAppResponse
}

// MarathonVersionResponse is the /v2/apps/{app_id}/versions/{version}
// response struct
type MarathonVersionResponse struct {
	ID, Version string
	Env         map[string]string
}

// MarathonApp is the result struct from getMarathonApp
type MarathonApp struct {
	ID, Version, TaskID string
	DeployKey           *[32]byte
	ServiceKey          *[32]byte
	Env                 map[string]string
}

func verifyRunningTask(appID string, appVersion string, taskID string, body []byte) (bool, error) {
	// Parse the JSON response
	var app MarathonAppsResponse
	err := json.Unmarshal(body, &app)
	if err != nil || app.App.ID != appID {
		return false, fmt.Errorf("Failed to parse Marathon JSON response (%s): %s", err, string(body))
	}

	// Check running tasks for this app and verify that the given taskId is present
	isActiveTaskid := false
	for _, task := range app.App.Tasks {
		if task.ID == taskID && task.Version == appVersion {
			isActiveTaskid = true
			break
		}
	}

	if !isActiveTaskid {
		return false, errors.New("Given taskId is not running (bug or hacking attempt?)")
	}

	return true, nil
}

func parseApplicationVersion(appID string, appVersion string, taskID string, body []byte) (*MarathonApp, error) {
	// Parse the JSON response
	var taskVersion MarathonVersionResponse
	err := json.Unmarshal(body, &taskVersion)
	if err != nil || taskVersion.ID != appID || taskVersion.Version != appVersion {
		return nil, fmt.Errorf("Failed to parse Marathon JSON response (%s): %s", err, string(body))
	}

	// Extract the deploy public key
	encodedDeployKey, ok := taskVersion.Env["DEPLOY_PUBLIC_KEY"]
	if !ok {
		return nil, errors.New("App is missing $DEPLOY_PUBLIC_KEY in the Marathon config \"env\" section")
	}

	deployKey, err := pemDecode(encodedDeployKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode $DEPLOY_PUBLIC_KEY (%s)", err)
	}

	// Extract the optional service public key
	encodedServiceKey, ok := taskVersion.Env["SERVICE_PUBLIC_KEY"]
	var serviceKey *[32]byte
	if ok {
		serviceKey, err = pemDecode(encodedServiceKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode $SERVICE_PUBLIC_KEY (%s)", err)
		}
	}

	return &MarathonApp{ID: taskVersion.ID, Version: taskVersion.Version,
		TaskID: taskID, DeployKey: deployKey, ServiceKey: serviceKey,
		Env: taskVersion.Env}, nil
}

func getMarathonApp(marathonURL string, appID string, appVersion string, taskID string) (*MarathonApp, error) {
	// Validate that given taskId is actually still running (old deploy keys shouldn't be allows to access any secrets)
	{
		// Fetch the list of running tasks for this app
		url := fmt.Sprintf("%s/v2/apps/%s?embed=apps.tasks", marathonURL,
			strings.Replace(strings.Replace(url.QueryEscape(strings.TrimLeft(appID, "/")), "..", "", -1), "%2F", "/", -1))
		body, err := httpGet(url)
		if err != nil {
			return nil, err
		}

		ok, err := verifyRunningTask(appID, appVersion, taskID, body)
		if !ok {
			return nil, err
		}
	}

	// Fetch the exact app config version for this task
	url := fmt.Sprintf("%s/v2/apps/%s/versions/%s", marathonURL,
		strings.Replace(strings.Replace(url.QueryEscape(strings.TrimLeft(appID, "/")), "..", "", -1), "%2F", "/", -1),
		url.QueryEscape(appVersion))
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}

	return parseApplicationVersion(appID, appVersion, taskID, body)
}
