package util

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// CommandError is the checked exception thrown on runtime errors
type CommandError struct {
	msg string // description of error
	err error  // inner error
}

func (e *CommandError) Error() string { return e.msg }

// Panics with a message if the given error isn't nil
func Check(err error, a ...interface{}) {
	if err != nil {
		var msg string
		if len(a) > 0 {
			msg = fmt.Sprintf("%s (%s)", fmt.Sprintf(a[0].(string), a[1:]...), err)
		} else {
			msg = fmt.Sprintf("%s", err)
		}

		panic(&CommandError{msg, err})
	}
}

// Panics with a message if the given condition isn't true
func AssertThat(condition bool, msg string, a ...interface{}) {
	if !condition {
		panic(&CommandError{fmt.Sprintf(msg, a...), nil})
	}
}

// Min value
func Min(a int, b int) int {
	if a < b {
		return a
	}

	return b
}

func Max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}

func Ellipsis(input string, maxLength int) string {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) > maxLength {
		return fmt.Sprintf("%s...", strings.TrimSpace(trimmed[0:Max(maxLength-3, 0)]))
	}

	return trimmed
}

func Defaults(a ...string) string {
	for _, item := range a {
		if len(item) > 0 {
			return item
		}
	}

	return ""
}

// Strip whitespace from string
func StripWhitespace(a string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}

		return r
	}, a)
}

func HttpReadBody(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d Error: %s", response.StatusCode, Ellipsis(string(body), 256))
	}

	return body, nil
}

func HttpPostForm(url string, values url.Values) ([]byte, error) {
	response, err := http.PostForm(url, values)
	if err != nil {
		return nil, err
	}

	return HttpReadBody(response)
}

func HttpGet(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	return HttpReadBody(response)
}
