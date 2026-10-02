package document

import (
	"bytes"
	"sort"

	"github.com/yuin/goldmark/ast"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// Record which AST node emitted each range of HTML without altering either the
// AST or the rendered bytes. This also covers extension-generated elements,
// notably footnote IDs and links, and math renderer output.
type mappedBuffer struct {
	bytes.Buffer
	spans []renderSpan
}

func (b *mappedBuffer) Available() int { return int(^uint(0) >> 1) }
func (b *mappedBuffer) Buffered() int  { return b.Len() }
func (b *mappedBuffer) Flush() error   { return nil }

type renderSpan struct {
	start, end, source int
	raw                bool
}

type mapRendering struct {
	buf       *mappedBuffer
	positions map[ast.Node]int
}

func (o mapRendering) SetConfig(c *renderer.Config) {
	for i := range c.NodeRenderers {
		c.NodeRenderers[i].Value = mappedRenderer{
			NodeRenderer: c.NodeRenderers[i].Value.(renderer.NodeRenderer),
			mapping:      o,
		}
	}
}

type mappedRenderer struct {
	renderer.NodeRenderer
	mapping mapRendering
}

func (r mappedRenderer) SetOption(name renderer.OptionName, value any) {
	if s, ok := r.NodeRenderer.(renderer.SetOptioner); ok {
		s.SetOption(name, value)
	}
}

func (r mappedRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	r.NodeRenderer.RegisterFuncs(mappedRegisterer{reg, r.mapping})
}

type mappedRegisterer struct {
	renderer.NodeRendererFuncRegisterer
	mapping mapRendering
}

func (r mappedRegisterer) Register(kind ast.NodeKind, f renderer.NodeRendererFunc) {
	r.NodeRendererFuncRegisterer.Register(kind, func(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		b := r.mapping.buf
		start := b.Len()
		status, err := f(w, src, n, entering)
		if b.Len() > start {
			pos := r.mapping.positions[n]
			raw := false
			switch n := n.(type) {
			case *ast.RawHTML:
				raw = true
			case *ast.HTMLBlock:
				raw = true
				if !entering && n.HasClosure() {
					pos = n.ClosureLine.Start
				}
			}
			b.spans = append(b.spans, renderSpan{start, b.Len(), pos, raw})
		}
		return status, err
	})
}

func (b *mappedBuffer) lineAt(offset int, src []byte, base int) int {
	i := sort.Search(len(b.spans), func(i int) bool { return b.spans[i].end > offset })
	if i == len(b.spans) {
		return base + 1
	}
	s := b.spans[i]
	pos := max(0, min(s.source, len(src)))
	line := base + 1 + bytes.Count(src[:pos], []byte("\n"))
	if s.raw {
		line += bytes.Count(b.Bytes()[s.start:offset], []byte("\n"))
	}
	return line
}

// nodeStart returns positions supplied by Goldmark, not matches against the
// whole source (which could accidentally point at a code sample or definition).
func nodeStart(n ast.Node) (int, bool) {
	switch n := n.(type) {
	case *ast.Text:
		return n.Segment.Start, true
	case *ast.RawHTML:
		if n.Segments.Len() > 0 {
			return n.Segments.At(0).Start, true
		}
	}
	if n.Type() == ast.TypeBlock && n.Lines().Len() > 0 {
		return n.Lines().At(0).Start, true
	}
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if p, ok := nodeStart(c); ok {
			return p, true
		}
	}
	return 0, false
}

func nodeEnd(n ast.Node) int {
	switch n := n.(type) {
	case *ast.Text:
		return n.Segment.Stop
	case *ast.RawHTML:
		if n.Segments.Len() > 0 {
			return n.Segments.At(n.Segments.Len() - 1).Stop
		}
	}
	for c := n.LastChild(); c != nil; c = c.PreviousSibling() {
		if p := nodeEnd(c); p > 0 {
			return p
		}
	}
	return 0
}

func blockSegments(n ast.Node) *text.Segments {
	for ; n != nil; n = n.Parent() {
		if n.Type() == ast.TypeBlock && n.Lines().Len() > 0 {
			return n.Lines()
		}
	}
	return nil
}

// Inline nodes without source segments (autolinks and footnote references)
// are located inside their containing block, after earlier siblings. Reference
// links use the occurrence's label, never the reference definition's position.
func sourcePositions(doc ast.Node, src []byte) map[ast.Node]int {
	positions := make(map[ast.Node]int)
	var walk func(ast.Node, int)
	walk = func(n ast.Node, fallback int) {
		pos, known := nodeStart(n)
		if !known {
			pos = fallback
		}
		lower := fallback
		if p := n.PreviousSibling(); p != nil {
			lower = max(lower, nodeEnd(p))
		}
		find := func(needle []byte) (int, bool) {
			segments := blockSegments(n)
			if segments == nil {
				return 0, false
			}
			for i := range segments.Len() {
				s := segments.At(i)
				start := max(s.Start, lower)
				if start >= s.Stop {
					continue
				}
				if at := bytes.Index(src[start:s.Stop], needle); at >= 0 {
					return start + at, true
				}
			}
			return 0, false
		}
		switch n := n.(type) {
		case *ast.Link, *ast.Image:
			if known {
				// Label text normally starts immediately after '[', but it can
				// start on another line or inside emphasis/code.
				if at := bytes.LastIndexByte(src[max(0, lower):pos], '['); at >= 0 {
					pos = max(0, lower) + at
				}
			} else if at, ok := find([]byte("[")); ok {
				pos = at
			}
		case *ast.AutoLink:
			if at, ok := find(n.Label(src)); ok {
				pos = at
			}
		case *east.FootnoteLink:
			if at, ok := find([]byte("[^")); ok {
				pos = at
			}
		}
		positions[n] = pos
		cursor := pos
		for c := n.FirstChild(); c != nil; c = c.NextSibling() {
			walk(c, cursor)
			cursor = max(cursor, nodeEnd(c))
		}
	}
	walk(doc, 0)
	return positions
}
