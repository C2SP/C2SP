package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"c2sp.org/C2SP/.github/linkcheck"
	"c2sp.org/C2SP/website/document"
	"c2sp.org/C2SP/website/spec"
	mathml "github.com/filippo-agent/goldmark-mathml"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

func main() {
	root := flag.String("root", "", "repository root (default: current Git repository)")
	base := flag.String("base", "", "base commit for regression checks (default: full audit)")
	linksOnly := flag.Bool("links-only", false, "skip specification formatting checks")
	annotations := flag.Bool("github-actions", os.Getenv("GITHUB_ACTIONS") == "true", "emit GitHub Actions annotations")
	flag.Parse()
	if *root == "" {
		out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, "lint: locate repository:", err)
			os.Exit(1)
		}
		*root = strings.TrimSpace(string(out))
	}
	paths, err := filepath.Glob(filepath.Join(*root, "*.md"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "lint:", err)
		os.Exit(1)
	}
	failed := false
	if !*linksOnly {
		for _, path := range paths {
			for _, e := range lintSpec(path) {
				printDiagnostic(os.Stdout, linkcheck.Diagnostic{
					File: filepath.Base(path), Message: e,
				}, *annotations)
				failed = true
			}
		}
	}
	diagnostics, err := linkcheck.Check(*root, *base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lint:", err)
		os.Exit(1)
	}
	for _, d := range diagnostics {
		printDiagnostic(os.Stdout, d, *annotations)
		failed = failed || !d.Existing
	}
	if failed {
		os.Exit(1)
	}
}

func printDiagnostic(w io.Writer, d linkcheck.Diagnostic, annotations bool) {
	location := d.File
	if d.Line > 0 {
		location += fmt.Sprintf(":%d", d.Line)
	}
	if d.Existing {
		// Prefix continuation lines too, so an ID containing a newline cannot
		// inject a workflow command while reporting pre-existing debt.
		message := strings.ReplaceAll(d.Message, "\r", "\\r")
		message = strings.ReplaceAll(message, "\n", "\n  ")
		location = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(location)
		fmt.Fprintf(w, "existing: %s: %s\n", location, message)
		return
	}
	if !annotations {
		fmt.Fprintf(w, "%s: %s\n", location, d.Message)
		return
	}
	// Escape workflow command data, including untrusted Markdown and file names.
	escape := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	propertyEscape := strings.NewReplacer(":", "%3A", ",", "%2C")
	properties := ""
	if d.File != "" {
		properties = " file=" + propertyEscape.Replace(escape.Replace(d.File))
		if d.Line > 0 {
			properties += fmt.Sprintf(",line=%d", d.Line)
		}
	}
	fmt.Fprintf(w, "::error%s::%s\n", properties, escape.Replace(d.Message))
}

// lintSpec checks that a spec has a valid name and starts with the front
// matter, warning box, and title heading described in MANUAL.md.
func lintSpec(path string) []string {
	var errs []string
	name := strings.TrimSuffix(filepath.Base(path), ".md")
	if !spec.ValidName(name) {
		errs = append(errs, "invalid spec name")
	}

	info, err := os.Lstat(path)
	if err != nil {
		return append(errs, err.Error())
	}
	if !info.Mode().IsRegular() {
		return append(errs, "specification must be a regular file, not a symlink")
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

// Formatting lint uses the shared parser, validating math separately in strict
// mode while historical document rendering remains tolerant.
var markdown = document.NewMarkdown()

// githubSpecLinkRE matches GitHub content links to a top-level spec document,
// which should use https://c2sp.org/<name> links instead.
var githubSpecLinkRE = regexp.MustCompile(
	`^https://(github\.com/C2SP/C2SP/(blob|tree|raw)|raw\.githubusercontent\.com/C2SP/C2SP)/[^/]+/[a-zA-Z0-9-]+\.md([#?]|$)`)

// lintBody checks the document's formatting and GitHub-link policy. Fragment
// validation uses the rendered document and repository graph in linkcheck.
func lintBody(body string) []string {
	var errs []string
	if err := document.ValidateMath([]byte(body)); err != nil {
		if mathErr, ok := errors.AsType[*mathml.RenderError](err); ok {
			errs = append(errs, fmt.Sprintf("invalid mathematical expression: %v", mathErr))
		} else {
			errs = append(errs, fmt.Sprintf("failed to render Markdown: %v", err))
		}
	}
	doc := markdown.Parser().Parse(text.NewReader([]byte(body)))

	h1s := 0
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		h, ok := n.(*ast.Heading)
		if !ok {
			return ast.WalkContinue, nil
		}

		if h.Level == 1 {
			h1s++
		}
		return ast.WalkSkipChildren, nil
	})
	if h1s != 1 {
		errs = append(errs, fmt.Sprintf("%d top-level headings, expected exactly one", h1s))
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
