package main

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCheck(t *testing.T) {
	// Handle checked errors nicely
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case *CommandError:
				assert.Equal(t, "Test Error (Inner Error)", fmt.Sprintf("%s", err))
			default:
				t.Errorf("Expected to catch a CommandError but got %v", err)
			}
		}
	}()

	check(errors.New("Inner Error"), "Test Error")
}

func TestAssert(t *testing.T) {
	// Handle checked errors nicely
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case *CommandError:
				assert.Equal(t, "Test Error", fmt.Sprintf("%s", err))
			default:
				t.Errorf("Expected to catch a CommandError but got %v", err)
			}
		}
	}()

	assertThat(false, "Test Error")
}

func TestMin(t *testing.T) {
	assert.Equal(t, 1, min(1, 2))
	assert.Equal(t, 1, min(2, 1))
}

func TestMax(t *testing.T) {
	assert.Equal(t, 2, max(1, 2))
	assert.Equal(t, 2, max(2, 1))
}

func TestEllipsis(t *testing.T) {
	assert.Equal(t, "123", ellipsis("123", 5))
	assert.Equal(t, "12345", ellipsis("12345", 5))
	assert.Equal(t, "12...", ellipsis("123456", 5))
	assert.Equal(t, "", ellipsis("", 5))
}

func TestDefaults(t *testing.T) {
	assert.Equal(t, "abc", defaults("abc", "123"))
	assert.Equal(t, "123", defaults("", "123"))
	assert.Equal(t, "", defaults("", ""))
	assert.Equal(t, "", defaults(""))
	assert.Equal(t, "", defaults())
}
