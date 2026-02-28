package main

import (
	"testing"

	"github.com/cespare/webtest"
)

func TestHandler(t *testing.T) {
	webtest.TestHandler(t, "*_test.txt", handler())
}
