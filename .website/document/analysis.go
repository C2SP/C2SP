package document

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/yuin/goldmark/ast"
	"golang.org/x/net/html"
)

type Link struct {
	Destination string
	Line        int
}

type Problem struct {
	Line    int
	Message string
}

type elementSource struct {
	line       int
	attributes map[string]int
}

// attributeOffsets is only a source-position helper over an already recognized
// HTML start-tag token. The HTML parser, never this scanner, decides which
// attributes and elements exist. Track quoting so e.g. title='href="fake"'
// cannot move the real href's location to an earlier line.
func attributeOffsets(raw []byte) map[string]int {
	space := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
	}
	result := make(map[string]int)
	i := 1 // skip '<'
	for i < len(raw) && !space(raw[i]) && raw[i] != '>' && raw[i] != '/' {
		i++
	}
	for i < len(raw) {
		for i < len(raw) && space(raw[i]) {
			i++
		}
		if i == len(raw) || raw[i] == '>' || raw[i] == '/' {
			break
		}
		start := i
		for i < len(raw) && !space(raw[i]) && raw[i] != '>' && raw[i] != '/' &&
			(raw[i] != '=' || i == start) {
			i++
		}
		key := strings.ToLower(string(raw[start:i]))
		if _, exists := result[key]; !exists {
			result[key] = start
		}
		for i < len(raw) && space(raw[i]) {
			i++
		}
		if i == len(raw) || raw[i] != '=' {
			continue
		}
		i++
		for i < len(raw) && space(raw[i]) {
			i++
		}
		if i < len(raw) && (raw[i] == '"' || raw[i] == '\'') {
			quote := raw[i]
			i++
			for i < len(raw) && raw[i] != quote {
				i++
			}
			if i < len(raw) {
				i++
			}
		} else {
			for i < len(raw) && !space(raw[i]) && raw[i] != '>' {
				i++
			}
		}
	}
	return result
}

// key deliberately includes all attributes: HTML parsing can discard tokens,
// insert implicit elements, and reorder table content. Matching by element
// identity instead of traversal order keeps positions attached to their source.
func elementKey(tag string, attrs []html.Attribute) string {
	var parts []string
	for _, a := range attrs {
		key := a.Key
		if a.Namespace != "" {
			key = a.Namespace + ":" + key
		}
		// Tree construction adjusts SVG camel-case names and splits xlink
		// attribute namespaces, unlike the tokenizer.
		parts = append(parts, strings.ToLower(key)+"\x00"+a.Val)
	}
	sort.Strings(parts)
	return strings.ToLower(tag) + "\x01" + strings.Join(parts, "\x01")
}

func (d *Document) addAnchor(id string, line int) {
	if id == "" {
		d.Problems = append(d.Problems, Problem{line, "empty rendered anchor"})
	}
	if first, ok := d.Anchors[id]; ok {
		d.Problems = append(d.Problems, Problem{line,
			fmt.Sprintf("duplicate rendered anchor %q (first defined on line %d)", id, first)})
	} else {
		d.Anchors[id] = line
	}
}

func (d *Document) analyze(buf *mappedBuffer, src []byte, base int, title *ast.Heading, home bool) {
	d.Anchors = make(map[string]int)
	if title != nil {
		pos, _ := nodeStart(title)
		d.addAnchor(d.TitleID, base+1+bytes.Count(src[:pos], []byte("\n")))
	}
	// The homepage inserts this heading through the index template. Reserve it
	// without consuming a Markdown slug; aliases must not renumber headings.
	if home {
		d.addAnchor("specifications", 0)
	}

	lines := make(map[string][]elementSource)
	z := html.NewTokenizer(bytes.NewReader(buf.Bytes()))
	offset := 0
	for {
		tt := z.Next()
		rawLen := len(z.Raw())
		if tt == html.ErrorToken {
			if z.Err() != io.EOF {
				d.Problems = append(d.Problems, Problem{0, "failed to tokenize rendered HTML: " + z.Err().Error()})
			}
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			locations := make(map[string]int)
			// Token() unescapes attributes in place, so locate them first.
			for attr, at := range attributeOffsets(z.Raw()) {
				locations[attr] = buf.lineAt(offset+at, src, base)
			}
			t := z.Token()
			key := elementKey(t.Data, t.Attr)
			lines[key] = append(lines[key], elementSource{
				line: buf.lineAt(offset, src, base), attributes: locations,
			})
		}
		offset += rawLen
	}

	// Parse the actual rendered HTML, not source regexps or AST approximations.
	// Escaped code, comments, raw-text elements, and discarded malformed HTML
	// cannot manufacture anchors or outgoing links.
	// Body is inserted into the page's MAIN, after HEAD has closed. Starting
	// the parser in that same context prevents e.g. an ignored <head id="x">
	// token from becoming an anchor merely because it led the source fragment.
	root, err := html.Parse(io.MultiReader(
		strings.NewReader("<!doctype html><html><head></head><body><main>"),
		bytes.NewReader(buf.Bytes()),
		strings.NewReader("</main></body></html>"),
	))
	if err != nil {
		d.Problems = append(d.Problems, Problem{0, "failed to parse rendered HTML: " + err.Error()})
		return
	}
	var walk func(*html.Node, bool)
	walk = func(n *html.Node, inert bool) {
		if n.Type == html.ElementNode {
			key := elementKey(n.Data, n.Attr)
			position := elementSource{line: base + 1}
			if queue := lines[key]; len(queue) > 0 {
				position = queue[0]
				lines[key] = queue[1:]
			}
			seen := make(map[string]bool)
			elementAnchors := make(map[string]bool)
			for _, a := range n.Attr {
				// Browsers use the first occurrence of a duplicate attribute.
				if a.Namespace != "" || seen[a.Key] {
					continue
				}
				seen[a.Key] = true
				line := position.line
				if at, ok := position.attributes[a.Key]; ok {
					line = at
				}
				if inert {
					continue
				}
				switch {
				case n.Namespace == "" && n.Data == "base" && a.Key == "href":
					// A base URL also rewrites generated section permalinks
					// and site navigation. Documents must not override it.
					d.Problems = append(d.Problems, Problem{line, "HTML <base href> is not supported: it changes section-link resolution"})
				case a.Key == "id", n.Data == "a" && a.Key == "name":
					// id and legacy name on the same A can designate the
					// same target. Only distinct elements collide.
					if !elementAnchors[a.Val] {
						d.addAnchor(a.Val, line)
						elementAnchors[a.Val] = true
					}
				case (n.Data == "a" || n.Data == "area") && a.Key == "href":
					d.Links = append(d.Links, Link{a.Val, line})
				}
			}
		}
		// HTML template contents live in an inert document fragment. Still
		// consume their source metadata so identical live elements following
		// a template retain their own positions.
		inert = inert || n.Type == html.ElementNode && n.Namespace == "" && n.Data == "template"
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, inert)
		}
	}
	walk(root, false)
}
