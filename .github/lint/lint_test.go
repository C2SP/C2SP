package main

import (
	"strings"
	"testing"
)

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
