package main

import (
	"cmp"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cespare/webtest"
)

func TestHandler(t *testing.T) {
	t.Run("Live", func(t *testing.T) {
		repo, err := InitRepo(t.Context(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		webtest.TestHandler(t, "handler_test.txt", handler(repo))
	})
	t.Run("Imported", func(t *testing.T) {
		repo, marks, err := ImportRepo(t.Context(), "testrepo_export.txt", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s, err := os.ReadFile("testrepo_test.txt")
		if err != nil {
			t.Fatal(err)
		}
		script := string(s)
		// Sort marks longest-first so ":18" is replaced before ":1".
		sortedMarks := slices.SortedFunc(maps.Keys(marks),
			func(a, b string) int { return cmp.Compare(len(b), len(a)) })
		for _, mark := range sortedMarks {
			hash := marks[mark]
			script = strings.ReplaceAll(script, mark+"!", hash[:16])
			script = strings.ReplaceAll(script, mark, hash)
		}
		tmpf := t.TempDir() + "/testrepo_test.txt"
		if err := os.WriteFile(tmpf, []byte(script), 0644); err != nil {
			t.Fatal(err)
		}
		webtest.TestHandler(t, tmpf, handler(repo))
	})
}
