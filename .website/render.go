package main

import (
	"strings"

	"c2sp.org/C2SP/website/document"
)

type frontMatter = document.FrontMatter
type renderedDoc = document.Document

// Keep the website's internal entry points for callers and existing tests.
var splitFrontMatter = document.SplitFrontMatter
var renderMarkdown = document.Render
var markdownSource = document.Source

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
