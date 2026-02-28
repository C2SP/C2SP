package main

import (
	"testing"

	"github.com/cespare/webtest"
)

func TestHandler(t *testing.T) {
	repo, err := InitRepo(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	webtest.TestHandler(t, "*_test.txt", handler(repo))
}
