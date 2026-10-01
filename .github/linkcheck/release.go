package linkcheck

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"c2sp.org/C2SP/.github/speclint"
	"c2sp.org/C2SP/website/document"
	"c2sp.org/C2SP/website/spec"
)

// lintRelease applies publication policy only to the specification and commit
// selected by a .new-tag proposal. It must not run on every source visited by
// the link graph: other specs may still be in development, and existing tags
// cannot be edited to comply with new release policies.
func lintRelease(src *source) []*failure {
	var failures []*failure
	// Run the current linter implementation on the selected blob, never the
	// linter code (or all the other specs) from the historical commit.
	problems := speclint.Check(strings.TrimSuffix(src.path, ".md"), src.record.data)
	problems = append(problems, lintPlaceholders(src.record.data)...)
	for _, p := range problems {
		failures = append(failures, &failure{
			source: src, line: p.Line,
			key:     "release-lint:" + p.Message,
			message: fmt.Sprintf("release at commit %s: %s", src.ref, p.Message),
			phase:   "release preflight",
		})
	}
	for _, link := range src.record.doc.Links {
		target, err := spec.ParseLink(link.Destination, src.public)
		if err != nil || target.Ignore || target.Local || target.Name == "" {
			// The normal graph walk diagnoses malformed or broken links.
			// Project documents have no tagged versions.
			continue
		}
		// Bare and @latest links are allowed even if they currently select
		// main: an untagged dependency has no released version to reference.
		if target.Version != "main" {
			continue
		}
		advice := "use the bare spec URL, or pin a released version"
		if target.Path == src.path && target.Fragment != "" {
			advice = "use a local #fragment link to refer to this release"
		}
		failures = append(failures, &failure{
			source: src, line: link.Line,
			key:     "release-main-link:" + link.Destination,
			message: fmt.Sprintf("release at commit %s must not link to @main: %s; %s", src.ref, link.Destination, advice),
			phase:   "release preflight",
		})
	}
	return failures
}

var placeholderRE = regexp.MustCompile(`TODO|TK|TBD|FIXME`)

// Check the source, including comments and code: unfinished examples are also
// unsuitable for publication. Match exact uppercase words, not substrings of
// identifiers (including Unicode identifiers). Task lists are not prohibited.
func lintPlaceholders(src []byte) []document.Problem {
	word := func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r) ||
			unicode.IsMark(r) || unicode.Is(unicode.Pc, r)
	}
	var problems []document.Problem
	for _, loc := range placeholderRE.FindAllIndex(src, -1) {
		before, _ := utf8.DecodeLastRune(src[:loc[0]])
		after, _ := utf8.DecodeRune(src[loc[1]:])
		if word(before) || word(after) {
			continue
		}
		problems = append(problems, document.Problem{
			Line:    1 + bytes.Count(src[:loc[0]], []byte("\n")),
			Message: "unfinished " + string(src[loc[0]:loc[1]]) + " placeholder",
		})
	}
	return problems
}
