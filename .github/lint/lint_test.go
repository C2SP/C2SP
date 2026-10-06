package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/not/a/document", filepath.Join(dir, "foo.md")); err != nil {
		t.Fatal(err)
	}
	errs := lintSpec(filepath.Join(dir, "foo.md"))
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "regular file") {
		t.Fatalf("symlink was read: %v", errs)
	}
}
