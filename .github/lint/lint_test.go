package main

import (
	"errors"
	"strings"
	"testing"

	mathml "github.com/filippo-agent/goldmark-mathml"
)

func TestLintRenderError(t *testing.T) {
	mathErr := &mathml.RenderError{Expression: `\frac{`, Err: errors.New("parse error")}
	if got := lintRenderError(mathErr); !strings.HasPrefix(got, "invalid mathematical expression:") {
		t.Fatalf("math error classified as %q", got)
	}
	if got := lintRenderError(errors.New("writer failed")); got != "failed to render Markdown: writer failed" {
		t.Fatalf("generic error classified as %q", got)
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
