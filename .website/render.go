package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"regexp"
	"strings"

	"c2sp.org/C2SP/website/spec"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	ghtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"go.yaml.in/yaml/v2"
)

// markdown renders GitHub Flavored Markdown. Raw HTML is allowed: all
// rendered content comes from the C2SP repository itself.
var markdown = goldmark.New(
	goldmark.WithExtensions(extension.GFM, extension.Footnote),
	goldmark.WithRendererOptions(ghtml.WithUnsafe()),
)

type frontMatter struct {
	Description string `yaml:"description"`
}

// splitFrontMatter parses and removes a leading YAML front matter block
// delimited by "---" lines. If src has no front matter, it is returned
// unchanged with a zero frontMatter.
func splitFrontMatter(src []byte) (frontMatter, []byte, error) {
	var fm frontMatter
	line, rest, found := bytes.Cut(src, []byte("\n"))
	if !found || string(bytes.TrimRight(line, "\r")) != "---" {
		return fm, src, nil
	}
	var yamlSrc []byte
	for len(rest) > 0 {
		line, r, _ := bytes.Cut(rest, []byte("\n"))
		rest = r
		if string(bytes.TrimRight(line, "\r")) == "---" {
			if err := yaml.Unmarshal(yamlSrc, &fm); err != nil {
				return frontMatter{}, rest, err
			}
			return fm, rest, nil
		}
		yamlSrc = append(yamlSrc, line...)
		yamlSrc = append(yamlSrc, '\n')
	}
	// Unterminated front matter: treat the whole document as content.
	return frontMatter{}, src, nil
}

type renderedDoc struct {
	Title       string
	Description string
	Body        template.HTML
}

// renderMarkdown renders a Markdown document to HTML. The title is extracted
// from the first top-level heading, which is removed from the body (pages
// display it as part of their own header). If specName is not empty, a
// leading "editor's copy" warning box mentioning c2sp.org/<specName> is
// dropped, as the website header replaces it. If stripLogo is set, a leading
// raw HTML block containing the logo is dropped (used for the README, which
// carries a GitHub-oriented logo header).
func renderMarkdown(src []byte, specName string, stripLogo bool) (*renderedDoc, error) {
	fm, body, err := splitFrontMatter(src)
	if err != nil {
		log.Printf("invalid front matter (rendering anyway): %v", err)
	}

	doc := markdown.Parser().Parse(text.NewReader(body))

	if specName != "" {
		stripBoilerplate(doc, body, specName)
		stripSpecURLs(doc, body, specName)
	}
	if stripLogo {
		stripLeadingHTMLBlock(doc, body)
	}
	transformAlerts(doc, body)

	var title string
	h1 := firstH1(doc)
	if h1 != nil {
		title = spec.Text(h1, body)
	}

	addHeadingIDs(doc, body)
	if h1 != nil {
		doc.RemoveChild(doc, h1)
	}

	var buf bytes.Buffer
	if err := markdown.Renderer().Render(&buf, body, doc); err != nil {
		return nil, err
	}
	return &renderedDoc{
		Title:       title,
		Description: fm.Description,
		Body:        template.HTML(buf.String()),
	}, nil
}

func firstH1(doc ast.Node) *ast.Heading {
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if h, ok := c.(*ast.Heading); ok && h.Level == 1 {
			return h
		}
	}
	return nil
}

// stripBoilerplate removes the warning box aimed at GitHub readers ("This is
// the editor's copy, ...") from the top of a spec. It is identified as a
// WARNING alert within the first two blocks that links to the spec's own
// c2sp.org page. Documents without it (such as old tagged versions) are left
// untouched.
func stripBoilerplate(doc ast.Node, source []byte, specName string) {
	c := doc.FirstChild()
	for range 2 {
		if c == nil {
			return
		}
		if bq, ok := c.(*ast.Blockquote); ok {
			if alertKind(bq, source) == "warning" &&
				strings.Contains(spec.Text(bq, source), "c2sp.org/"+specName) {
				doc.RemoveChild(doc, bq)
				return
			}
		}
		c = c.NextSibling()
	}
}

// markdownSource returns the Markdown source as served to text/markdown
// clients: without the front matter and, for specs, without the GitHub
// editor's copy warning boilerplate, both of which would confuse readers
// that are already fetching from c2sp.org.
func markdownSource(src []byte, specName string) []byte {
	_, body, _ := splitFrontMatter(src)
	if specName != "" {
		body = stripBoilerplateSource(body, specName)
	}
	return body
}

// stripBoilerplateSource is the Markdown source equivalent of
// stripBoilerplate: it removes a warning alert blockquote mentioning the
// spec's own c2sp.org page from the start of the document.
func stripBoilerplateSource(body []byte, specName string) []byte {
	lineAt := func(i int) (line []byte, next int) {
		if nl := bytes.IndexByte(body[i:], '\n'); nl >= 0 {
			return body[i : i+nl], i + nl + 1
		}
		return body[i:], len(body)
	}

	// Skip leading blank lines.
	i := 0
	for i < len(body) {
		line, next := lineAt(i)
		if len(bytes.TrimSpace(line)) > 0 {
			break
		}
		i = next
	}

	line, next := lineAt(i)
	marker := bytes.TrimSpace(line)
	if !bytes.HasPrefix(marker, []byte(">")) {
		return body
	}
	marker = bytes.TrimSpace(marker[1:])
	if !bytes.Equal(marker, []byte("[!WARNING]")) {
		return body
	}

	// Consume the rest of the blockquote.
	end := next
	for end < len(body) {
		line, next := lineAt(end)
		if !bytes.HasPrefix(bytes.TrimSpace(line), []byte(">")) {
			break
		}
		end = next
	}

	if !bytes.Contains(body[i:end], []byte("c2sp.org/"+specName)) {
		return body
	}
	return bytes.TrimLeft(body[end:], "\r\n")
}

// stripSpecURLs removes the short paragraph of spec URLs that conventionally
// follows the title, like "c2sp.org/age, age-encryption.org/v1", which the
// website header replaces. The length limit keeps prose introductions that
// happen to mention the spec's URL.
func stripSpecURLs(doc ast.Node, source []byte, specName string) {
	h1 := firstH1(doc)
	if h1 == nil {
		return
	}
	p, ok := h1.NextSibling().(*ast.Paragraph)
	if !ok {
		return
	}
	text := spec.Text(p, source)
	if len(text) < 100 && strings.Contains(text, "c2sp.org/"+specName) {
		doc.RemoveChild(doc, p)
	}
}

// stripLeadingHTMLBlock removes the document's first block if it is a raw
// HTML block containing the repository logo.
func stripLeadingHTMLBlock(doc ast.Node, source []byte) {
	b, ok := doc.FirstChild().(*ast.HTMLBlock)
	if !ok {
		return
	}
	var content []byte
	for i := range b.Lines().Len() {
		seg := b.Lines().At(i)
		content = append(content, seg.Value(source)...)
	}
	if bytes.Contains(content, []byte(".logo/")) {
		doc.RemoveChild(doc, b)
	}
}

var alertRE = regexp.MustCompile(`^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]$`)

// alertKind returns the lowercase kind of a GitHub alert blockquote ("note",
// "tip", "important", "warning", or "caution"), or "" if bq is a regular
// blockquote.
func alertKind(bq *ast.Blockquote, source []byte) string {
	p, ok := bq.FirstChild().(*ast.Paragraph)
	if !ok || p.Lines().Len() == 0 {
		return ""
	}
	seg := p.Lines().At(0)
	first := bytes.TrimSpace(seg.Value(source))
	m := alertRE.FindSubmatch(first)
	if m == nil {
		return ""
	}
	return strings.ToLower(string(m[1]))
}

// transformAlerts turns GitHub alert blockquotes into <blockquote> elements
// with an "alert alert-<kind>" class, removing the [!KIND] marker line. The
// visible label is added by CSS.
func transformAlerts(doc ast.Node, source []byte) {
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		bq, ok := n.(*ast.Blockquote)
		if !ok {
			return ast.WalkContinue, nil
		}
		kind := alertKind(bq, source)
		if kind == "" {
			return ast.WalkContinue, nil
		}
		bq.SetAttribute([]byte("class"), []byte("alert alert-"+kind))

		// Remove the inline nodes of the marker line.
		p := bq.FirstChild().(*ast.Paragraph)
		markerEnd := p.Lines().At(0).Stop
		for c := p.FirstChild(); c != nil; {
			next := c.NextSibling()
			t, ok := c.(*ast.Text)
			if !ok || t.Segment.Start >= markerEnd {
				break
			}
			p.RemoveChild(p, c)
			c = next
		}
		if p.ChildCount() == 0 {
			bq.RemoveChild(bq, p)
		}
		return ast.WalkContinue, nil
	})
}

// addHeadingIDs assigns GitHub-compatible anchor IDs to all headings, so that
// links to GitHub-rendered sections keep working, and appends a clickable
// anchor link to each heading.
func addHeadingIDs(doc ast.Node, source []byte) {
	var s spec.Slugger
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		h, ok := n.(*ast.Heading)
		if !ok {
			return ast.WalkContinue, nil
		}
		id := s.Slug(spec.Text(h, source))
		h.SetAttribute([]byte("id"), []byte(id))
		anchor := ast.NewString(fmt.Appendf(nil,
			`&nbsp;<a class="anchor" href="#%s" aria-label="Link to this section">&sect;</a>`, id))
		anchor.SetCode(true)
		h.AppendChild(h, anchor)
		return ast.WalkSkipChildren, nil
	})
}

// parseMaintainers extracts the maintainers of a spec from MAINTAINERS.md,
// which lists them as "- [@handle](https://github.com/handle)" bullets under
// a "### <spec-name>" heading. The heading is matched case-insensitively, as
// some section names differ from the spec file name in case.
func parseMaintainers(md []byte, specName string) []string {
	var handles []string
	inSection := false
	for line := range strings.Lines(string(md)) {
		line = strings.TrimSpace(line)
		if h, ok := strings.CutPrefix(line, "### "); ok {
			inSection = strings.EqualFold(strings.TrimSpace(h), specName)
			continue
		}
		if strings.HasPrefix(line, "#") {
			inSection = false
			continue
		}
		if !inSection {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "- [@"); ok {
			if handle, _, ok := strings.Cut(rest, "]"); ok {
				handles = append(handles, handle)
			}
		}
	}
	return handles
}
