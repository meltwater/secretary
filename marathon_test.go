package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestVerifyRunningTask(t *testing.T) {
	response, err := ioutil.ReadFile("./resources/test/marathon-apps-response.json")
	assert.Nil(t, err)

	ok, err := verifyRunningTask("/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d", response)
	assert.True(t, ok)

	// Verify that appId is checked
	ok, err = verifyRunningTask("/demo/webap1", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d", response)
	assert.False(t, ok)

	// Verify that appVersion is checked
	ok, err = verifyRunningTask("/demo/webapp", "2014-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d", response)
	assert.False(t, ok)

	// Verify that taskId is checked
	ok, err = verifyRunningTask("/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webap1.0f810e10-9a82-11e5-94c7-6a515f434e2d", response)
	assert.False(t, ok)

	// Verify bad responses
	ok, err = verifyRunningTask("/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d", []byte(`{}`))
	assert.False(t, ok)

	// Verify bad responses
	ok, err = verifyRunningTask("/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d", []byte(`{"app": {}}`))
	assert.False(t, ok)

	// Verify bad responses
	ok, err = verifyRunningTask("/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d", []byte(`%"#¤%"#¤`))
	assert.False(t, ok)
}

func TestParseApplicationVersion(t *testing.T) {
	response, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	app, err := parseApplicationVersion("/demo/webapp", "2015-12-04T12:25:08.426Z", response)
	assert.Nil(t, err)
	assert.Equal(t, "/demo/webapp", app.Id)
	assert.Equal(t, "2015-12-04T12:25:08.426Z", app.Version)

	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(app.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", encode(app.ServiceKey[:]))

	// Verify that appId is checked
	app, err = parseApplicationVersion("/demo/webap1", "2015-12-04T12:25:08.426Z", response)
	assert.Nil(t, app)
	assert.NotNil(t, err)

	// Verify that appVersion is checked
	app, err = parseApplicationVersion("/demo/webapp", "2014-12-04T12:25:08.426Z", response)
	assert.Nil(t, app)
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion("/demo/webapp", "2015-12-04T12:25:08.426Z", []byte(`{}`))
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion("/demo/webapp", "2015-12-04T12:25:08.426Z", []byte(`{"id": "/demo/webapp"}`))
	assert.NotNil(t, err)

	// Verify bad responses
	app, err = parseApplicationVersion("/demo/webapp", "2015-12-04T12:25:08.426Z", []byte(`%"#¤%"#¤`))
	assert.NotNil(t, err)
}

func TestParseApplicationWithoutServiceKey(t *testing.T) {
	response, err := ioutil.ReadFile("./resources/test/marathon-versions-nosvckey.json")
	assert.Nil(t, err)

	app, err := parseApplicationVersion("/demo/webapp", "2015-12-04T12:25:08.426Z", response)
	assert.Nil(t, err)
	assert.Equal(t, "/demo/webapp", app.Id)
	assert.Equal(t, "2015-12-04T12:25:08.426Z", app.Version)

	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(app.DeployKey[:]))
	assert.Nil(t, app.ServiceKey)
}

func TestParseApplicationWithoutDeployKey(t *testing.T) {
	response, err := ioutil.ReadFile("./resources/test/marathon-versions-nodepkey.json")
	assert.Nil(t, err)

	_, err = parseApplicationVersion("/demo/webapp", "2015-12-04T12:25:08.426Z", response)
	assert.NotNil(t, err)
	assert.Equal(t, "App is missing $DEPLOY_PUBLIC_KEY in the Marathon config \"env\" section", err.Error())
}
