package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitFrontMatter(t *testing.T) {
	tests := []struct {
		name, src       string
		wantDescription string
		wantBody        string
		wantErr         bool
	}{
		{"none", "# Title\n\nBody.\n", "", "# Title\n\nBody.\n", false},
		{"present", "---\ndescription: A test spec\n---\n# Title\n", "A test spec", "# Title\n", false},
		{"crlf", "---\r\ndescription: A test spec\r\n---\r\n# Title\r\n", "A test spec", "# Title\r\n", false},
		{"unterminated", "---\ndescription: A test spec\n", "", "---\ndescription: A test spec\n", false},
		{"invalid", "---\n\t: x\n---\n# Title\n", "", "# Title\n", true},
		{"empty", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, body, err := splitFrontMatter([]byte(tt.src))
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if fm.Description != tt.wantDescription {
				t.Errorf("Description = %q, want %q", fm.Description, tt.wantDescription)
			}
			if string(body) != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestRenderMarkdown(t *testing.T) {
	src := `---
description: A test spec
---
> [!WARNING]
> This document is the editor's copy. For a stable rendered reference,
> use [c2sp.org/foo](https://c2sp.org/foo).

# The Foo Specification

Some intro.

## The ` + "`keyed_hash`" + ` Section

> [!NOTE]
> Something worth noting, with
> a second line.

## Dup

## Dup

> A regular blockquote.
`
	doc, err := renderMarkdown([]byte(src), "foo", false)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "The Foo Specification" {
		t.Errorf("Title = %q", doc.Title)
	}
	if doc.Description != "A test spec" {
		t.Errorf("Description = %q", doc.Description)
	}
	body := string(doc.Body)
	for _, want := range []string{
		`<h2 id="the-keyed_hash-section">`,
		`<a class="anchor" href="#the-keyed_hash-section"`,
		`<h2 id="dup">`,
		`<h2 id="dup-1">`,
		`<blockquote class="alert alert-note">`,
		`Something worth noting`,
		"<blockquote>\n<p>A regular blockquote.</p>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q\nbody: %s", want, body)
		}
	}
	for _, notWant := range []string{
		"editor's copy",
		"[!WARNING]",
		"[!NOTE]",
		"<h1",
	} {
		if strings.Contains(body, notWant) {
			t.Errorf("body contains %q\nbody: %s", notWant, body)
		}
	}
}

func TestRenderMarkdownLegacy(t *testing.T) {
	// Old tagged versions have no front matter and no warning boilerplate.
	src := "# Old Spec\n\nContent with a [link](https://example.com).\n"
	doc, err := renderMarkdown([]byte(src), "foo", false)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "Old Spec" {
		t.Errorf("Title = %q", doc.Title)
	}
	if doc.Description != "" {
		t.Errorf("Description = %q", doc.Description)
	}
	if !strings.Contains(string(doc.Body), `<a href="https://example.com">link</a>`) {
		t.Errorf("body = %s", doc.Body)
	}
}

func TestStripSpecURLs(t *testing.T) {
	tests := []struct {
		name, src string
		want      []string
		notWant   []string
	}{
		{"links", "# Foo\n\n[c2sp.org/foo](https://c2sp.org/foo),\n[foo.example](https://foo.example)\n\nIntro.\n",
			[]string{"Intro."}, []string{"foo.example"}},
		{"bare", "# Foo\n\nhttps://c2sp.org/foo\n\nIntro.\n",
			[]string{"Intro."}, []string{"c2sp.org/foo"}},
		{"prose without URL", "# Foo\n\nFoo is a spec that will be widely deployed.\n",
			[]string{"widely deployed"}, nil},
		{"long prose with URL", "# Foo\n\nThis specification, published at c2sp.org/foo, describes " +
			"a novel construction that has many words in its first paragraph indeed.\n",
			[]string{"c2sp.org/foo"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := renderMarkdown([]byte(tt.src), "foo", false)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.want {
				if !strings.Contains(string(doc.Body), want) {
					t.Errorf("body does not contain %q\nbody: %s", want, doc.Body)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(string(doc.Body), notWant) {
					t.Errorf("body contains %q\nbody: %s", notWant, doc.Body)
				}
			}
		})
	}
}

func TestRenderMarkdownH1Dedup(t *testing.T) {
	// The removed H1 must still count towards slug deduplication, since
	// GitHub renders it.
	src := "# Dup\n\n## Dup\n"
	doc, err := renderMarkdown([]byte(src), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc.Body), `<h2 id="dup-1">`) {
		t.Errorf("body = %s", doc.Body)
	}
}

func TestRenderMarkdownStripLogo(t *testing.T) {
	src := `<p align="center">
  <picture>
    <img src="/.logo/logo.svg">
  </picture>
</p>

# The Project

Prose.
`
	doc, err := renderMarkdown([]byte(src), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.Body), "picture") {
		t.Errorf("logo block not stripped: %s", doc.Body)
	}
	if !strings.Contains(string(doc.Body), "<p>Prose.</p>") {
		t.Errorf("body = %s", doc.Body)
	}
}

func TestMarkdownSource(t *testing.T) {
	spec := `---
description: A test spec
---

> [!WARNING]
> This is the editor's copy.
> For a stable rendered reference, use https://c2sp.org/foo.

# Foo

Content.
`
	tests := []struct {
		name, src, specName, want string
	}{
		{"full", spec, "foo", "# Foo\n\nContent.\n"},
		{"legacy", "# Foo\n\nContent.\n", "foo", "# Foo\n\nContent.\n"},
		{"other warning kept", "> [!WARNING]\n> Interoperability hazard.\n\n# Foo\n", "foo",
			"> [!WARNING]\n> Interoperability hazard.\n\n# Foo\n"},
		{"doc keeps blockquotes", "> [!WARNING]\n> See https://c2sp.org/foo.\n\n# Doc\n", "",
			"> [!WARNING]\n> See https://c2sp.org/foo.\n\n# Doc\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(markdownSource([]byte(tt.src), tt.specName)); got != tt.want {
				t.Errorf("markdownSource = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRenderRepoSpecs renders every spec in the repository, checking that the
// front matter, warning boilerplate, and title conform to what the website
// expects.
func TestRenderRepoSpecs(t *testing.T) {
	paths, err := filepath.Glob("../*.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no specs found")
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".md")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := renderMarkdown(src, name, false)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Title == "" {
				t.Error("no title")
			}
			if doc.Description == "" {
				t.Error("no front matter description")
			}
			if strings.Contains(string(doc.Body), "editor&#39;s copy") {
				t.Error("warning boilerplate not stripped")
			}
			if md := markdownSource(src, name); strings.Contains(string(md), "editor's copy") {
				t.Error("warning boilerplate not stripped from Markdown source")
			}
		})
	}
}

func TestParseMaintainers(t *testing.T) {
	md := []byte(`## Stewards

- [@steward1](https://github.com/steward1)

## Specification Maintainers

### bar

- [@one](https://github.com/one)
- [@two](https://github.com/two)

### foo

- [@three](https://github.com/three)
`)
	tests := []struct {
		name string
		want []string
	}{
		{"bar", []string{"one", "two"}},
		{"BAR", []string{"one", "two"}},
		{"foo", []string{"three"}},
		{"baz", nil},
	}
	for _, tt := range tests {
		got := parseMaintainers(md, tt.name)
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("parseMaintainers(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
