package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meltwater/secretary/box"
	"github.com/stretchr/testify/assert"
)

func TestVerifyRunningTask(t *testing.T) {
	appID, appVersion, taskID := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-apps-response.json")
	assert.Nil(t, err)

	ok, err := verifyRunningTask(appID, appVersion, taskID, response)
	assert.True(t, ok)
	assert.Nil(t, err)

	// Verify that appID is checked
	ok, err = verifyRunningTask("/demo/webap1", appVersion, taskID, response)
	assert.False(t, ok)
	assert.NotNil(t, err)

	// Verify that appVersion is checked
	ok, err = verifyRunningTask(appID, "2014-12-04T12:25:08.426Z", taskID, response)
	assert.False(t, ok)
	assert.NotNil(t, err)

	// Verify that taskID is checked
	ok, err = verifyRunningTask(appID, appVersion, "demo_webap1.0f810e10-9a82-11e5-94c7-6a515f434e2d", response)
	assert.False(t, ok)
	assert.NotNil(t, err)

	// Verify bad responses
	ok, err = verifyRunningTask(appID, appVersion, taskID, []byte(`{}`))
	assert.False(t, ok)
	assert.NotNil(t, err)

	// Verify bad responses
	ok, err = verifyRunningTask(appID, appVersion, taskID, []byte(`{"app": {}}`))
	assert.False(t, ok)
	assert.NotNil(t, err)

	// Verify bad responses
	ok, err = verifyRunningTask(appID, appVersion, taskID, []byte(`%"#¤%"#¤`))
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestParseApplicationVersion(t *testing.T) {
	appID, appVersion, taskID := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	app, err := parseApplicationVersion(appID, appVersion, taskID, response)
	assert.Nil(t, err)
	assert.Equal(t, appID, app.ID)
	assert.Equal(t, appVersion, app.Version)
	assert.Equal(t, taskID, app.TaskID)
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", box.Encode(app.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", box.Encode(app.ServiceKey[:]))

	// Verify that appID is checked
	app, err = parseApplicationVersion("/demo/webap1", "2015-12-04T12:25:08.426Z", taskID, response)
	assert.Nil(t, app)
	assert.NotNil(t, err)

	// Verify that appVersion is checked
	app, err = parseApplicationVersion(appID, "2014-12-04T12:25:08.426Z", taskID, response)
	assert.Nil(t, app)
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion(appID, appVersion, taskID, []byte(`{}`))
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion(appID, appVersion, taskID, []byte(`{"id": "/demo/webapp"}`))
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion(appID, appVersion, taskID, []byte(`%"#¤%"#¤`))
	assert.NotNil(t, err)
}

func TestParseApplicationWithoutServiceKey(t *testing.T) {
	appID, appVersion, taskID := "/demo/webapp2", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-versions-nosvckey.json")
	assert.Nil(t, err)

	app, err := parseApplicationVersion(appID, appVersion, taskID, response)
	assert.Nil(t, err)
	assert.Equal(t, appID, app.ID)
	assert.Equal(t, appVersion, app.Version)
	assert.Equal(t, taskID, app.TaskID)

	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", box.Encode(app.DeployKey[:]))
	assert.Nil(t, app.ServiceKey)
}

func TestParseApplicationWithoutDeployKey(t *testing.T) {
	appID, appVersion, taskID := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"

	response, err := ioutil.ReadFile("./resources/test/marathon-versions-nodepkey.json")
	assert.Nil(t, err)

	_, err = parseApplicationVersion(appID, appVersion, taskID, response)
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
	assert.Equal(t, "/demo/webapp", app.ID)
	assert.Equal(t, "2015-12-04T12:25:08.426Z", app.Version)
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", box.Encode(app.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", box.Encode(app.ServiceKey[:]))
	assert.Equal(t, "ENC[NACL,", app.Env["DATABASE_PASSWORD"][0:9])
}
