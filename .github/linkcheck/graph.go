package linkcheck

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"c2sp.org/C2SP/website/spec"
)

func (f *failure) signature() string {
	return f.occurrenceKey(f.key)
}

func (f *failure) occurrenceKey(key string) string {
	return fmt.Sprintf("%s|%d|%s", f.source.id(), f.line, key)
}

// Source positions belong in display text, not in a failure's stable identity.
// The analyzer currently puts the first-definition position in duplicates.
var firstDefinitionLineRE = regexp.MustCompile(` \(first defined on line [0-9]+\)$`)

func (s *snapshot) walk() error {
	seen := make(map[string]bool)
	for {
		var pending []string
		for id, src := range s.sources {
			if !seen[id] && src.record != nil && src.record.doc != nil {
				pending = append(pending, id)
			}
		}
		if len(pending) == 0 {
			return nil
		}
		sort.Strings(pending)
		for _, id := range pending {
			src := s.sources[id]
			seen[id] = true
			for _, problem := range src.record.doc.Problems {
				s.failures = append(s.failures, &failure{
					source: src, line: problem.Line, key: "document:" + firstDefinitionLineRE.ReplaceAllString(problem.Message, ""),
					message: problem.Message, phase: s.phase,
				})
			}
			for _, link := range src.record.doc.Links {
				target, err := spec.ParseLink(link.Destination, src.public)
				if err != nil {
					s.failures = append(s.failures, &failure{
						source: src, line: link.Line, key: "route:" + link.Destination,
						message: err.Error(), phase: s.phase,
					})
					continue
				}
				if target.Ignore {
					continue
				}
				// The current check is always performed with the real inventory.
				// A second, separate snapshot performs post-proposal checks.
				currentMain, err := s.check(src, link.Line, link.Destination, target, false)
				if err != nil {
					return err
				}
				if !target.Local && target.Name != "" && target.Version == "latest" && !currentMain {
					if _, err := s.check(src, link.Line, link.Destination, target, true); err != nil {
						return err
					}
				}
			}
		}
	}
}

// check returns whether the check resolved to candidate main, so the identical
// future check can be omitted when latest already falls back to main.
func (s *snapshot) check(src *source, line int, destination string, target spec.Target, future bool) (bool, error) {
	var dest *source
	var err error
	main := false
	kind := "current"
	if future {
		kind = "future"
	}
	switch {
	case target.Local:
		dest = src
	case future || target.Version == "main" || target.Name == "":
		main = true
		public := "/" + target.Name + "@main"
		if target.Name == "" {
			for route, p := range spec.ProjectDocuments {
				if p == target.Path {
					public = route
					break
				}
			}
		}
		dest, err = s.load(target.Path, "main", s.ref, public)
	case target.Version == "latest":
		var versions []string
		for tag := range s.tags {
			if name, version, _ := strings.Cut(tag, "/"); name == target.Name {
				versions = append(versions, version)
			}
		}
		version := spec.LatestVersion(versions)
		if version == "" {
			main = true
			dest, err = s.load(target.Path, "main", s.ref, "/"+target.Name+"@main")
		} else {
			dest, err = s.load(target.Path, version, s.tags[target.Name+"/"+version], "/"+target.Name+"@"+version)
		}
	case spec.ValidCommit(target.Version):
		var commit string
		commit, err = s.repo.commit(target.Version, s.tip)
		if err == nil {
			dest, err = s.load(target.Path, commit, commit, "/"+target.Name+"@"+commit)
		}
	default:
		ref, ok := s.tags[target.Name+"/"+target.Version]
		if !ok {
			err = fmt.Errorf("missing version %s@%s", target.Name, target.Version)
		} else {
			dest, err = s.load(target.Path, target.Version, ref, "/"+target.Name+"@"+target.Version)
		}
	}
	if invalidInput(err) {
		return false, err
	}
	if err == nil && target.Fragment != "" {
		if _, exists := dest.record.doc.Anchors[target.Fragment]; !exists {
			err = fmt.Errorf("missing anchor #%s in %s", target.Fragment, dest.label())
		}
	}
	if err != nil {
		qualifier := "current resolution"
		if future {
			qualifier = "future release (candidate main)"
		}
		s.failures = append(s.failures, &failure{
			source: src, line: max(line, 1),
			key:     kind + ":" + destination,
			message: fmt.Sprintf("%s: %s: %v", destination, qualifier, err),
			target:  target, main: main, phase: s.phase,
		})
	}
	return main, nil
}

func diagnostics(candidate, base *snapshot) []Diagnostic {
	var result []Diagnostic
	grouped := make(map[string][]*failure)
	for _, f := range candidate.failures {
		// A suggestion is appropriate only for an anchor that actually existed,
		// not for typo links, nonexistent versions, or deleted files.
		if f.main && f.target.Fragment != "" {
			dest := candidate.sources[f.target.Path+"@main"]
			if dest != nil && dest.record != nil {
				_, present := dest.record.doc.Anchors[f.target.Fragment]
				if !present && (oldAnchor(base, f.target.Path, f.target.Fragment) > 0 ||
					releasedAnchor(candidate, f.target.Path, f.target.Fragment)) {
					key := f.phase + "|" + f.target.Path + "|" + f.target.Fragment
					grouped[key] = append(grouped[key], f)
					continue
				}
			}
		}
		result = append(result, diagnostic(f))
	}
	for _, key := range sortedKeys(grouped) {
		group := grouped[key]
		first := group[0]
		p, fragment := first.target.Path, first.target.Fragment
		line := oldAnchor(base, p, fragment)
		word := "missing"
		if line > 0 {
			word = "removed"
			line = destinationLine(base.sources[p+"@main"].record.data,
				candidate.sources[p+"@main"].record.data, line)
		} else {
			line = 1
		}
		message := fmt.Sprintf("%s anchor #%s is still referenced", word, fragment)
		if first.phase != "" {
			message = first.phase + ": " + message
		}
		allExisting := true
		refs := make(map[string]bool)
		for _, f := range group {
			allExisting = allExisting && f.existing
			ref := fmt.Sprintf("  %s:%d: %s", f.source.label(), f.line, f.message)
			refs[ref] = true
		}
		for _, ref := range sortedKeys(refs) {
			message += "\n" + ref
		}
		// Attribute escaping preserves the exact decoded ID, including Unicode,
		// quotes and duplicate-heading suffixes.
		message += fmt.Sprintf("\n  If this section was renamed, preserve the old destination with <a id=\"%s\"></a> immediately before the replacement heading.", escapeAttribute(fragment))
		result = append(result, Diagnostic{File: p, Line: line, Message: message, Existing: allExisting})
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Existing != b.Existing {
			return !a.Existing
		}
		return a.Message < b.Message
	})
	return result
}

func diagnostic(f *failure) Diagnostic {
	message := f.message
	if f.source.version != "main" {
		message = f.source.label() + ": " + message
	}
	if f.phase != "" {
		message = f.phase + ": " + message
	}
	return Diagnostic{File: f.source.path, Line: max(f.line, 1), Message: message, Existing: f.existing}
}

func oldAnchor(s *snapshot, p, fragment string) int {
	if s == nil {
		return 0
	}
	src := s.sources[p+"@main"]
	if src == nil || src.record == nil || src.record.doc == nil {
		return 0
	}
	return src.record.doc.Anchors[fragment]
}

func releasedAnchor(s *snapshot, p, fragment string) bool {
	name := strings.TrimSuffix(p, ".md")
	for tag := range s.tags {
		specName, version, _ := strings.Cut(tag, "/")
		if specName != name {
			continue
		}
		src := s.sources[p+"@"+version]
		if src == nil || src.record == nil || src.record.doc == nil {
			continue
		}
		if _, ok := src.record.doc.Anchors[fragment]; ok {
			return true
		}
	}
	return false
}

func escapeAttribute(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(value)
}

// If the exact old line was deleted, annotate the next surviving line (or the
// end of the changed file), without claiming it is the replacement heading.
func destinationLine(old, new []byte, oldLine int) int {
	mapping, err := unchangedLines(old, new)
	if err != nil {
		return 1
	}
	line, distance := 1, int(^uint(0)>>1)
	for candidate, previous := range mapping {
		d := previous - oldLine
		if d >= 0 && d < distance {
			line, distance = candidate, d
		}
	}
	return max(1, min(line, strings.Count(string(new), "\n")+1))
}
