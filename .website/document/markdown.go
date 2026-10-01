package document

import (
	"io"

	mathml "github.com/filippo-agent/goldmark-mathml"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	ghtml "github.com/yuin/goldmark/renderer/html"
)

// NewMarkdown returns the website's Markdown configuration. Rendering is
// tolerant of invalid math, showing the same escaped error box as the website.
// Raw HTML is allowed because these documents come from the project repository.
func NewMarkdown() goldmark.Markdown {
	return newMarkdown(mathml.New(mathml.WithErrorFallback(nil)))
}

func newMarkdown(math goldmark.Extender) goldmark.Markdown {
	return goldmark.New(
		goldmark.WithExtensions(extension.GFM, extension.Footnote, math),
		goldmark.WithRendererOptions(ghtml.WithUnsafe()),
	)
}

// ValidateMath uses the identical Markdown parser but fails on invalid math
// rather than rendering an error box. Formatting lint can use this independently
// of the tolerant analysis needed for historical documents.
func ValidateMath(src []byte) error {
	return newMarkdown(mathml.New()).Convert(src, io.Discard)
}
