package document

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// UndefinedReferences checks full [text][label] and collapsed [label][] links
// (including images), and [^label] footnotes. Problems refer to the opening
// bracket's original source line, including any front matter.
//
// Undefined shortcut references [label] are deliberately not reported: they
// cannot be distinguished from ordinary bracketed prose such as [array].
// Definitions and syntax are interpreted by NewMarkdown, not a source regexp.
// In particular, Goldmark normalizes ordinary reference labels with Unicode
// case folding and whitespace collapsing, but matches footnote labels as exact
// bytes (including case, whitespace, and escapes).
func UndefinedReferences(src []byte) []Problem {
	_, body, _ := SplitFrontMatter(src)
	check := &referenceCheck{
		source: body,
		base:   bytes.Count(src[:len(src)-len(body)], []byte("\n")),
	}
	md := NewMarkdown()
	md.Parser().AddOptions(check)
	md.Parser().Parse(text.NewReader(body))
	sort.SliceStable(check.problems, func(i, j int) bool {
		return check.problems[i].Line < check.problems[j].Line
	})
	return check.problems
}

type referenceCheck struct {
	source   []byte
	base     int
	problems []Problem
}

func (c *referenceCheck) report(start int, message string) {
	c.problems = append(c.problems, Problem{
		Line:    c.base + 1 + bytes.Count(c.source[:start], []byte("\n")),
		Message: message,
	})
}

// Decorate the configured parsers rather than adding an independent bracket
// grammar. Config, InlineParser, CloseBlocker, Context, and Reader are public
// Goldmark APIs. Identify the default parsers by their constructors' types;
// their private state and context keys are never inspected.
func (c *referenceCheck) SetParserOption(config *parser.Config) {
	for i, p := range config.InlineParsers {
		switch reflect.TypeOf(p.Value) {
		case reflect.TypeOf(parser.NewLinkParser()):
			config.InlineParsers[i].Value = &referenceLinkParser{
				InlineParser: p.Value.(parser.InlineParser), check: c,
			}
		case reflect.TypeOf(extension.NewFootnoteParser()):
			config.InlineParsers[i].Value = &referenceFootnoteParser{
				InlineParser: p.Value.(parser.InlineParser), check: c,
			}
		}
	}
}

type referenceOpening struct {
	node  ast.Node
	start int
}

type referenceLinkParser struct {
	parser.InlineParser
	check    *referenceCheck
	openings []referenceOpening
}

func (p *referenceLinkParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	line, before := block.Position()
	char := block.Peek()
	if char != ']' {
		n := p.InlineParser.Parse(parent, block, pc)
		if n != nil {
			p.openings = append(p.openings, referenceOpening{n, before.Start})
		}
		return n
	}

	// Closed/replaced markers are detached by the real link parser. Retain
	// only its still-live opening nodes, so nested labels and images use the
	// correct start even when the label contains emphasis or code.
	for len(p.openings) > 0 && p.openings[len(p.openings)-1].node.Parent() == nil {
		p.openings = p.openings[:len(p.openings)-1]
	}
	if len(p.openings) == 0 {
		return p.InlineParser.Parse(parent, block, pc)
	}
	start := p.openings[len(p.openings)-1].start
	block.Advance(1)
	_, shortcut := block.Position()
	block.SetPosition(line, before)
	context := &referenceLookup{
		Context: pc,
		missing: func(label string) {
			_, after := block.Position()
			// A full or collapsed reference has consumed its second pair of
			// brackets at lookup time. For a shortcut lookup (including a
			// failed inline link), Goldmark rewinds to just after the first
			// closing bracket. Leave those ambiguous shortcuts alone.
			if after.Start > shortcut.Start {
				p.check.report(start, fmt.Sprintf("undefined Markdown reference %q", label))
			}
		},
	}
	return p.InlineParser.Parse(parent, block, context)
}

func (p *referenceLinkParser) CloseBlock(parent ast.Node, block text.Reader, pc parser.Context) {
	p.InlineParser.(parser.CloseBlocker).CloseBlock(parent, block, pc)
	p.openings = nil
}

type referenceLookup struct {
	parser.Context
	missing func(string)
}

func (c *referenceLookup) Reference(label string) (parser.Reference, bool) {
	ref, ok := c.Context.Reference(label)
	if !ok {
		c.missing(label)
	}
	return ref, ok
}

type referenceFootnoteParser struct {
	parser.InlineParser
	check *referenceCheck
}

func (p *referenceFootnoteParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	_, before := block.Position()
	n := p.InlineParser.Parse(parent, block, pc)
	_, after := block.Position()
	// Goldmark consumes the complete footnote syntax before consulting its
	// definitions, returning nil only if no matching definition exists. If
	// the syntax was not a footnote it leaves the reader unchanged.
	if n == nil && after.Start > before.Start {
		raw := block.Value(text.NewSegment(before.Start, after.Start))
		open := bytes.IndexByte(raw, '^') + 1
		label := raw[open : len(raw)-1]
		// Empty/blank labels cannot define footnotes and are malformed
		// syntax rather than unresolved references.
		if !util.IsBlank(label) {
			p.check.report(before.Start, fmt.Sprintf("undefined footnote reference %q", label))
		}
	}
	return n
}
