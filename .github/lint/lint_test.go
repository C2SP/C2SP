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
	if len(errs) != 1 || !strings.Contains(errs[0], "regular file") {
		t.Fatalf("symlink was read: %v", errs)
	}
}

func TestLintMath(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		invalid bool
	}{
		{name: "valid inline", body: "# Test\n\n$x^2$\n"},
		{name: "valid display", body: "# Test\n\n```math\nx^2\n```\n"},
		{name: "invalid inline", body: "# Test\n\n$\\frac{$\n", invalid: true},
		{name: "invalid display", body: "# Test\n\n```math\n\\frac{\n```\n", invalid: true},
		{name: "invalid TeX in code", body: "# Test\n\n`$\\frac{$`\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errs := lintBody(test.body)
			found := false
			for _, err := range errs {
				if strings.HasPrefix(err, "invalid mathematical expression:") {
					found = true
				}
			}
			if found != test.invalid {
				t.Fatalf("invalid math error = %v, want %v; errors: %v", found, test.invalid, errs)
			}
		})
	}
}
