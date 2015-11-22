package main

import (
	"errors"
	"fmt"
	a "github.com/stretchr/testify/assert"
	"testing"
)

func TestCheck(t *testing.T) {
	// Handle checked errors nicely
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case *CommandError:
				a.Equal(t, "Test Error (Inner Error)", fmt.Sprintf("%s", err))
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
				a.Equal(t, "Test Error", fmt.Sprintf("%s", err))
			default:
				t.Errorf("Expected to catch a CommandError but got %v", err)
			}
		}
	}()

	assert(false, "Test Error")
}
