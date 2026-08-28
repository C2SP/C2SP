package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"c2sp.org/C2SP/website/spec"
	mathml "github.com/filippo-agent/goldmark-mathml"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"
)

func main() {
	paths, err := filepath.Glob("../../*.md")
	if err != nil {
		panic(err)
	}
	failed := false
	for _, path := range paths {
		for _, e := range lintSpec(path) {
			fmt.Printf("%s: %s\n", filepath.Base(path), e)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// lintSpec checks that a spec has a valid name and starts with the front
// matter, warning box, and title heading described in MANUAL.md.
func lintSpec(path string) []string {
	var errs []string
	name := strings.TrimSuffix(filepath.Base(path), ".md")
	if !spec.ValidName(name) {
		errs = append(errs, "invalid spec name")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return append(errs, err.Error())
	}
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	line := func(i int) string {
		if i < len(lines) {
			return lines[i]
		}
		return ""
	}

	if line(0) != "---" {
		return append(errs, "missing front matter")
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if line(i) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return append(errs, "unterminated front matter")
	}
	var desc string
	for i := 1; i < end; i++ {
		if d, ok := strings.CutPrefix(line(i), "description: "); ok {
			desc = d
		}
	}
	switch {
	case desc == "":
		errs = append(errs, "missing front matter description")
	case len(desc) > 100:
		errs = append(errs, "front matter description longer than 100 characters")
	case strings.HasSuffix(desc, "."):
		errs = append(errs, "front matter description should not end with a period")
	}

	warning := []string{
		"",
		"> [!WARNING]",
		"> This is the editor's copy of this specification.",
		fmt.Sprintf("> For a stable rendered reference, use [c2sp.org/%s](https://c2sp.org/%s).", name, name),
		"",
	}
	for i, want := range warning {
		if got := line(end + 1 + i); got != want {
			errs = append(errs, fmt.Sprintf("line %d: %q, expected %q", end+2+i, got, want))
		}
	}

	if title := line(end + 1 + len(warning)); !strings.HasPrefix(title, "# ") {
		errs = append(errs, "missing title heading after the warning box")
	}

	// The body starts after the front matter, which would otherwise parse as
	// Markdown (the closing fence turns the description into a setext heading).
	body := strings.Join(lines[end+1:], "\n")
	return append(errs, lintBody(body)...)
}

// markdown must match the parser configuration of the website, which
// determines the anchors of the rendered pages.
var markdown = goldmark.New(goldmark.WithExtensions(
	extension.GFM,
	extension.Footnote,
	mathml.New(),
))

var htmlAnchorRE = regexp.MustCompile(`<a\s+(?:id|name)="([^"]+)"`)

// githubSpecLinkRE matches GitHub content links to a top-level spec document,
// which should use https://c2sp.org/<name> links instead.
var githubSpecLinkRE = regexp.MustCompile(
	`^https://(github\.com/C2SP/C2SP/(blob|tree|raw)|raw\.githubusercontent\.com/C2SP/C2SP)/[^/]+/[a-zA-Z0-9-]+\.md([#?]|$)`)

// lintBody checks that the document has exactly one top-level heading, and
// that all intra-document links resolve to a heading anchor.
func lintBody(body string) []string {
	var errs []string
	if err := markdown.Convert([]byte(body), io.Discard); err != nil {
		var mathErr *mathml.RenderError
		if errors.As(err, &mathErr) {
			errs = append(errs, fmt.Sprintf("invalid mathematical expression: %v", mathErr))
		} else {
			errs = append(errs, fmt.Sprintf("failed to render Markdown: %v", err))
		}
	}
	doc := markdown.Parser().Parse(text.NewReader([]byte(body)))

	anchors := make(map[string]bool)
	var s spec.Slugger
	h1s := 0
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		h, ok := n.(*ast.Heading)
		if !ok {
			return ast.WalkContinue, nil
		}
		anchors[s.Slug(spec.Text(h, []byte(body)))] = true
		if h.Level == 1 {
			h1s++
		}
		return ast.WalkSkipChildren, nil
	})
	if h1s != 1 {
		errs = append(errs, fmt.Sprintf("%d top-level headings, expected exactly one", h1s))
	}

	// Raw HTML anchors like <a id="foo"> are link targets, too.
	for _, m := range htmlAnchorRE.FindAllStringSubmatch(body, -1) {
		anchors[m[1]] = true
	}

	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var dest string
		switch n := n.(type) {
		case *ast.Link:
			dest = string(n.Destination)
		case *ast.Image:
			dest = string(n.Destination)
		case *ast.AutoLink:
			dest = string(n.URL([]byte(body)))
		default:
			return ast.WalkContinue, nil
		}
		if frag, ok := strings.CutPrefix(dest, "#"); ok && !anchors[frag] {
			errs = append(errs, fmt.Sprintf("broken anchor link #%s", frag))
		}
		// GitHub paths are not stable; specifications should be linked
		// through c2sp.org. Ancillary files and directories (such as test
		// vectors) have no c2sp.org equivalent and are allowed.
		if githubSpecLinkRE.MatchString(dest) {
			errs = append(errs, fmt.Sprintf("link to GitHub instead of c2sp.org: %s", dest))
		}
		return ast.WalkContinue, nil
	})
	return errs
}
