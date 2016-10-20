package util

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

	Check(errors.New("Inner Error"), "Test Error")
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

	AssertThat(false, "Test Error")
}

func TestMin(t *testing.T) {
	assert.Equal(t, 1, Min(1, 2))
	assert.Equal(t, 1, Min(2, 1))
}

func TestMax(t *testing.T) {
	assert.Equal(t, 2, Max(1, 2))
	assert.Equal(t, 2, Max(2, 1))
}

func TestEllipsis(t *testing.T) {
	assert.Equal(t, "123", Ellipsis("123", 5))
	assert.Equal(t, "12345", Ellipsis("12345", 5))
	assert.Equal(t, "12...", Ellipsis("123456", 5))
	assert.Equal(t, "", Ellipsis("", 5))
}

func TestDefaults(t *testing.T) {
	assert.Equal(t, "abc", Defaults("abc", "123"))
	assert.Equal(t, "123", Defaults("", "123"))
	assert.Equal(t, "", Defaults("", ""))
	assert.Equal(t, "", Defaults(""))
	assert.Equal(t, "", Defaults())
}

func TestStripWhitespace(t *testing.T) {
	assert.Equal(t, "abc", StripWhitespace(" a b c "))
	assert.Equal(t, "abc", StripWhitespace(" a b\n c "))
	assert.Equal(t, "abc", StripWhitespace(" a \r\nb\n c \n"))
}
