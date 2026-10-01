package main

import (
	"bytes"
	"strings"
	"testing"

	"c2sp.org/C2SP/.github/linkcheck"
)

func TestDiagnostic(t *testing.T) {
	d := linkcheck.Diagnostic{File: "foo.md", Line: 42, Message: "missing #old\nadd an alias"}
	var b bytes.Buffer
	printDiagnostic(&b, d, false)
	if got := b.String(); got != "foo.md:42: missing #old\nadd an alias\n" {
		t.Fatalf("text = %q", got)
	}
	b.Reset()
	printDiagnostic(&b, d, true)
	if got := b.String(); got != "::error file=foo.md,line=42::missing #old%0Aadd an alias\n" {
		t.Fatalf("annotation = %q", got)
	}
	b.Reset()
	d.File = "a,b:c%.md"
	d.Message = "bad%\r\n::warning::injected"
	printDiagnostic(&b, d, true)
	if got := b.String(); got != "::error file=a%2Cb%3Ac%25.md,line=42::bad%25%0D%0A::warning::injected\n" {
		t.Fatalf("escaped annotation = %q", got)
	}
	b.Reset()
	d.Existing = true
	d.Message = "existing debt"
	printDiagnostic(&b, d, true)
	if !strings.HasPrefix(b.String(), "existing: ") || strings.Contains(b.String(), "::error") {
		t.Fatalf("existing debt = %q", b.String())
	}
	b.Reset()
	d.File = "foo.md\n::error::injected"
	d.Message = "existing debt\n::error::injected"
	printDiagnostic(&b, d, true)
	if strings.Contains(b.String(), "\n::error") {
		t.Fatalf("existing debt injected a workflow command: %q", b.String())
	}
}
