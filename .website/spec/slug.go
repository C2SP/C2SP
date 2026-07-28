package spec

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/yuin/goldmark/ast"
)

// Slugger generates GitHub-compatible heading anchors: lowercase, keeping
// only word characters (letters, marks, numbers, and connectors), hyphens,
// and spaces, with each space replaced by a hyphen. Duplicate slugs get a
// numeric suffix.
type Slugger struct {
	seen map[string]int
}

func (s *Slugger) Slug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.Pc) || r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	slug := b.String()
	if s.seen == nil {
		s.seen = make(map[string]int)
	}
	n := s.seen[slug]
	s.seen[slug]++
	if n > 0 {
		return fmt.Sprintf("%s-%d", slug, n)
	}
	return slug
}

// Text extracts the plain text content of a Markdown node, approximating
// what GitHub feeds its heading slugger: text, code spans, and autolinks,
// with raw HTML dropped.
func Text(n ast.Node, source []byte) string {
	var b strings.Builder
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		switch n := n.(type) {
		case *ast.Text:
			b.Write(n.Segment.Value(source))
		case *ast.String:
			b.Write(n.Value)
		case *ast.AutoLink:
			b.Write(n.Label(source))
		default:
			for c := n.FirstChild(); c != nil; c = c.NextSibling() {
				walk(c)
			}
		}
	}
	walk(n)
	return b.String()
}
