package linkcheck

import (
	"fmt"
	"strings"

	"c2sp.org/C2SP/website/spec"
)

// lintRelease applies publication policy only to the specification and commit
// selected by a .new-tag proposal. It must not run on every source visited by
// the link graph: other specs may still be in development, and existing tags
// cannot be edited to comply with new release policies.
func (s *snapshot) lintRelease(src *source) []*failure {
	var failures []*failure
	for _, link := range src.record.doc.Links {
		target, err := spec.ParseLink(link.Destination, src.public)
		if err != nil || target.Ignore || target.Local || target.Name == "" {
			// The normal graph walk diagnoses malformed or broken links.
			// Project documents have no tagged versions.
			continue
		}
		reason := "must not link to @main"
		switch target.Version {
		case "main":
		case "latest":
			// Bare and @latest URLs fall back to main when the dependency
			// has no releases. Include all pending tags in this decision.
			tagged := false
			for tag := range s.tags {
				if strings.HasPrefix(tag, target.Name+"/") {
					tagged = true
					break
				}
			}
			if tagged {
				continue
			}
			reason = "must not link to an untagged specification (resolves to @main)"
		default:
			continue
		}
		advice := "link to a released version instead"
		if target.Path == src.path && target.Fragment != "" {
			advice = "use a local #fragment link to refer to this release"
		}
		failures = append(failures, &failure{
			source: src, line: link.Line,
			key:     "release-main-link:" + link.Destination,
			message: fmt.Sprintf("release at commit %s %s: %s; %s", src.ref, reason, link.Destination, advice),
			phase:   "release preflight",
		})
	}
	return failures
}
