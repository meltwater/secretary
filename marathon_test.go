package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyRunningTask(t *testing.T) {
	appId, appVersion, taskId := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-apps-response.json")
	assert.Nil(t, err)

	ok, err := verifyRunningTask(appId, appVersion, taskId, response)
	assert.True(t, ok)

	// Verify that appId is checked
	ok, err = verifyRunningTask("/demo/webap1", appVersion, taskId, response)
	assert.False(t, ok)

	// Verify that appVersion is checked
	ok, err = verifyRunningTask(appId, "2014-12-04T12:25:08.426Z", taskId, response)
	assert.False(t, ok)

	// Verify that taskId is checked
	ok, err = verifyRunningTask(appId, appVersion, "demo_webap1.0f810e10-9a82-11e5-94c7-6a515f434e2d", response)
	assert.False(t, ok)

	// Verify bad responses
	ok, err = verifyRunningTask(appId, appVersion, taskId, []byte(`{}`))
	assert.False(t, ok)

	// Verify bad responses
	ok, err = verifyRunningTask(appId, appVersion, taskId, []byte(`{"app": {}}`))
	assert.False(t, ok)

	// Verify bad responses
	ok, err = verifyRunningTask(appId, appVersion, taskId, []byte(`%"#¤%"#¤`))
	assert.False(t, ok)
}

func TestParseApplicationVersion(t *testing.T) {
	appId, appVersion, taskId := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	app, err := parseApplicationVersion(appId, appVersion, taskId, response)
	assert.Nil(t, err)
	assert.Equal(t, appId, app.Id)
	assert.Equal(t, appVersion, app.Version)
	assert.Equal(t, taskId, app.TaskId)
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(app.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", encode(app.ServiceKey[:]))

	// Verify that appId is checked
	app, err = parseApplicationVersion("/demo/webap1", "2015-12-04T12:25:08.426Z", taskId, response)
	assert.Nil(t, app)
	assert.NotNil(t, err)

	// Verify that appVersion is checked
	app, err = parseApplicationVersion(appId, "2014-12-04T12:25:08.426Z", taskId, response)
	assert.Nil(t, app)
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion(appId, appVersion, taskId, []byte(`{}`))
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion(appId, appVersion, taskId, []byte(`{"id": "/demo/webapp"}`))
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion(appId, appVersion, taskId, []byte(`%"#¤%"#¤`))
	assert.NotNil(t, err)
}

func TestParseApplicationWithoutServiceKey(t *testing.T) {
	appId, appVersion, taskId := "/demo/webapp2", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-versions-nosvckey.json")
	assert.Nil(t, err)

	app, err := parseApplicationVersion(appId, appVersion, taskId, response)
	assert.Nil(t, err)
	assert.Equal(t, appId, app.Id)
	assert.Equal(t, appVersion, app.Version)
	assert.Equal(t, taskId, app.TaskId)

	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(app.DeployKey[:]))
	assert.Nil(t, app.ServiceKey)
}

func TestParseApplicationWithoutDeployKey(t *testing.T) {
	appId, appVersion, taskId := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-versions-nodepkey.json")
	assert.Nil(t, err)

	_, err = parseApplicationVersion(appId, appVersion, taskId, response)
	assert.NotNil(t, err)
	assert.Equal(t, "App is missing $DEPLOY_PUBLIC_KEY in the Marathon config \"env\" section", err.Error())
}

func TestGetMarathonApp(t *testing.T) {
	appsResponse, err := ioutil.ReadFile("./resources/test/marathon-apps-response.json")
	assert.Nil(t, err)

	versionsResponse, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	// Start in-test HTTP server that emulates Marathon
	marathon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/apps/demo/webapp" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponse))
		case r.URL.Path == "/v2/apps/demo/webapp/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponse))
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer marathon.Close()

	app, err := getMarathonApp(marathon.URL, "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d")
	assert.Nil(t, err)
	assert.Equal(t, "/demo/webapp", app.Id)
	assert.Equal(t, "2015-12-04T12:25:08.426Z", app.Version)
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(app.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", encode(app.ServiceKey[:]))
	assert.Equal(t, "ENC[NACL,", app.Env["DATABASE_PASSWORD"][0:9])
}
