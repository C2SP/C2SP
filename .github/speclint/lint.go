// Package speclint validates specification source independently of how it was
// loaded. Working-tree and proposed-release checks always use this same code.
package speclint

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"c2sp.org/C2SP/website/document"
	"c2sp.org/C2SP/website/spec"
	mathml "github.com/filippo-agent/goldmark-mathml"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

type Problem = document.Problem

// Check applies the current specification lints to the supplied source, even
// when that source comes from an older commit. name excludes the .md suffix.
func Check(name string, data []byte) []Problem {
	var problems []Problem
	add := func(line int, message string) {
		problems = append(problems, Problem{Line: line, Message: message})
	}
	if !spec.ValidName(name) {
		add(1, "invalid spec name")
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
		add(1, "missing front matter")
		return problems
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if line(i) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		add(1, "unterminated front matter")
		return problems
	}
	var desc string
	descLine := 1
	for i := 1; i < end; i++ {
		if d, ok := strings.CutPrefix(line(i), "description: "); ok {
			desc, descLine = d, i+1
		}
	}
	switch {
	case desc == "":
		add(descLine, "missing front matter description")
	case len(desc) > 100:
		add(descLine, "front matter description longer than 100 characters")
	case strings.HasSuffix(desc, "."):
		add(descLine, "front matter description should not end with a period")
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
			add(end+2+i, fmt.Sprintf("%q, expected %q", got, want))
		}
	}
	if title := line(end + 1 + len(warning)); !strings.HasPrefix(title, "# ") {
		add(end+2+len(warning), "missing title heading after the warning box")
	}
	// Front matter is not Markdown; its closing fence could create a spurious
	// setext heading. Keep source positions relative to the original file.
	body := []byte(strings.Join(lines[end+1:], "\n"))
	for _, p := range Body(body) {
		p.Line += end + 1
		problems = append(problems, p)
	}
	return problems
}

// githubSpecLinkRE matches unstable links to top-level spec documents. Links to
// ancillary files and directories have no c2sp.org equivalent and are allowed.
var githubSpecLinkRE = regexp.MustCompile(
	`^https://(github\.com/C2SP/C2SP/(blob|tree|raw)|raw\.githubusercontent\.com/C2SP/C2SP)/[^/]+/[a-zA-Z0-9-]+\.md([#?]|$)`)

// Body checks math, heading structure, undefined references, and the GitHub-link
// policy. Destination resolution is checked by the repository graph.
func Body(body []byte) []Problem {
	problems := document.UndefinedReferences(body)
	if err := document.ValidateMath(body); err != nil {
		message := fmt.Sprintf("failed to render Markdown: %v", err)
		if mathErr, ok := errors.AsType[*mathml.RenderError](err); ok {
			message = fmt.Sprintf("invalid mathematical expression: %v", mathErr)
		}
		problems = append(problems, Problem{Line: 1, Message: message})
	}
	doc := document.NewMarkdown().Parser().Parse(text.NewReader(body))
	h1s := 0
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if h, ok := n.(*ast.Heading); ok && h.Level == 1 {
			h1s++
		}
		var dest string
		switch n := n.(type) {
		case *ast.Link:
			dest = string(n.Destination)
		case *ast.Image:
			dest = string(n.Destination)
		case *ast.AutoLink:
			dest = string(n.URL(body))
		}
		if githubSpecLinkRE.MatchString(dest) {
			problems = append(problems, Problem{
				Line: sourceLine(n, body), Message: "link to GitHub instead of c2sp.org: " + dest,
			})
		}
		return ast.WalkContinue, nil
	})
	if h1s != 1 {
		problems = append(problems, Problem{Line: 1, Message: fmt.Sprintf("%d top-level headings, expected exactly one", h1s)})
	}
	return problems
}

func sourceLine(n ast.Node, src []byte) int {
	for n != nil {
		if n.Type() == ast.TypeBlock && n.Lines().Len() > 0 {
			return 1 + bytes.Count(src[:n.Lines().At(0).Start], []byte("\n"))
		}
		n = n.Parent()
	}
	return 1
}
