// Package linkcheck checks the local, version-aware graph of served C2SP
// documents. It uses Git objects only and never contacts the website.
package linkcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"c2sp.org/C2SP/website/document"
	"c2sp.org/C2SP/website/spec"
	"golang.org/x/mod/semver"
)

// Diagnostic is a source-located failure. Existing failures remain visible but
// need not block a change. With no base, every diagnostic is new.
type Diagnostic struct {
	File     string
	Line     int
	Message  string
	Existing bool
}

type record struct {
	data []byte
	doc  *document.Document
}

type source struct {
	path, version, ref, public string
	record                     *record
}

func (s *source) id() string { return s.path + "@" + s.version }
func (s *source) label() string {
	if s.version == "main" {
		return s.path
	}
	return strings.TrimSuffix(s.path, ".md") + "@" + s.version
}

type failure struct {
	source   *source
	line     int
	key      string
	message  string
	target   spec.Target
	main     bool
	existing bool
	phase    string
}

type snapshot struct {
	repo     *repository
	ref, tip string
	tags     map[string]string // name/version -> immutable commit
	sources  map[string]*source
	failures []*failure
	phase    string
}

// Check checks the working tree against base (a local Git commit-ish), or
// performs a full audit if base is empty. Both sides use the same real tag
// inventory. Invalid/incomplete repository inputs are returned as errors.
func Check(root, base string) ([]Diagnostic, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	r := &repository{root: root, cache: make(map[string]*record)}
	if err := r.requireFullClone(); err != nil {
		return nil, err
	}
	shallow, err := r.git("rev-parse", "--is-shallow-repository")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(shallow)) != "false" {
		return nil, fmt.Errorf("section link checking requires a full, non-shallow repository (fetch full history and tags)")
	}
	// Check local connectivity without lazy-fetching missing objects.
	if _, err := r.git("fsck", "--connectivity-only", "--no-dangling"); err != nil {
		return nil, fmt.Errorf("incomplete repository: %w", err)
	}
	tipOut, err := r.git("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, err
	}
	tip := strings.TrimSpace(string(tipOut))
	tags, err := tagInventory(r)
	if err != nil {
		return nil, err
	}
	candidate, err := analyze(r, "", tip, tags, true)
	if err != nil {
		return nil, err
	}
	var previous *snapshot
	if base != "" {
		baseOut, err := r.git("rev-parse", "--verify", "--end-of-options", base+"^{commit}")
		if err != nil {
			return nil, fmt.Errorf("invalid base: %w", err)
		}
		base = strings.TrimSpace(string(baseOut))
		// Proposals are not published history. Even --base HEAD must gate a
		// committed .new-tag against actual tags, never its own virtual release.
		previous, err = analyze(r, base, base, tags, false)
		if err != nil {
			return nil, err
		}
		if err := markExisting(previous, candidate); err != nil {
			return nil, err
		}
	}
	return diagnostics(candidate, previous), nil
}

func tagInventory(r *repository) (map[string]string, error) {
	out, err := r.git("tag", "--list")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string)
	for _, tag := range strings.Fields(string(out)) {
		name, version, ok := strings.Cut(tag, "/")
		if !ok || !spec.ValidName(name) || !semver.IsValid(version) {
			continue
		}
		commit, err := r.git("rev-parse", "--verify", "--end-of-options", "refs/tags/"+tag+"^{commit}")
		if err != nil {
			return nil, fmt.Errorf("invalid spec tag %s: %w", tag, err)
		}
		tags[tag] = strings.TrimSpace(string(commit))
	}
	return tags, nil
}

func (s *snapshot) load(p, version, ref, public string) (*source, error) {
	id := p + "@" + version
	if src := s.sources[id]; src != nil {
		return src, nil
	}
	data, err := s.repo.read(ref, p)
	if err != nil {
		if invalidInput(err) {
			return nil, err
		}
		return nil, fmt.Errorf("missing document %s at %s", p, version)
	}
	name := ""
	if !strings.HasPrefix(p, ".github/") {
		name = strings.TrimSuffix(p, ".md")
	}
	hash := sha256.Sum256(data)
	stripLogo := p == ".github/README.md"
	cacheKey := fmt.Sprintf("%x:%s:%t", hash, name, stripLogo)
	rec := s.repo.cache[cacheKey]
	if rec == nil {
		doc, err := document.Render(data, name, stripLogo)
		if err != nil {
			return nil, fmt.Errorf("render %s at %s: %w", p, version, err)
		}
		rec = &record{data: data, doc: doc}
		s.repo.cache[cacheKey] = rec
	}
	src := &source{path: p, version: version, ref: ref, public: public, record: rec}
	s.sources[id] = src
	return src, nil
}

func analyze(r *repository, ref, tip string, tags map[string]string, checkProposals bool) (*snapshot, error) {
	s := &snapshot{repo: r, ref: ref, tip: tip, tags: tags, sources: make(map[string]*source)}
	paths, err := r.paths(ref)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		name, ok := strings.CutSuffix(p, ".md")
		if !ok || strings.Contains(p, "/") {
			continue
		}
		if _, err := s.load(p, "main", ref, "/"+name+"@main"); err != nil {
			return nil, err
		}
	}
	routes := make([]string, 0, len(spec.ProjectDocuments))
	for route := range spec.ProjectDocuments {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		p := spec.ProjectDocuments[route]
		// A repository need not have every project route (e.g. historical bases).
		// A link to a missing project document is still checked normally.
		if _, err := r.read(ref, p); err != nil {
			if invalidInput(err) {
				return nil, err
			}
			continue
		}
		if _, err := s.load(p, "main", ref, route); err != nil {
			return nil, err
		}
	}
	for _, tag := range sortedKeys(tags) {
		name, version, _ := strings.Cut(tag, "/")
		if _, err := s.load(name+".md", version, tags[tag], "/"+name+"@"+version); err != nil {
			src := &source{path: name + ".md", version: version}
			s.failures = append(s.failures, &failure{source: src, line: 1, key: "missing-tag-file", message: err.Error()})
		}
	}
	if err := s.walk(); err != nil {
		return nil, err
	}
	if !checkProposals {
		return s, nil
	}
	proposals := make(map[string]string)
	for _, p := range paths {
		if path.Base(p) != ".new-tag" || strings.Count(p, "/") != 1 {
			continue
		}
		data, err := r.read(ref, p)
		if err != nil {
			return nil, err
		}
		src := &source{path: p, version: "main", record: &record{data: data}}
		s.sources[src.id()] = src
		tag, commit, err := s.proposal(p, data)
		if err != nil {
			s.failures = append(s.failures, &failure{source: src, line: 1, key: "proposal:" + string(data), message: err.Error()})
			continue
		}
		proposals[tag] = commit
	}
	if len(proposals) > 0 {
		virtual := &snapshot{repo: r, ref: ref, tip: tip, tags: make(map[string]string), sources: make(map[string]*source), phase: "after proposed tags"}
		for tag, commit := range tags {
			virtual.tags[tag] = commit
		}
		for id, src := range s.sources {
			if src.record != nil && src.record.doc != nil {
				virtual.sources[id] = src
			}
		}
		var releases []*source
		for _, tag := range sortedKeys(proposals) {
			commit := proposals[tag]
			virtual.tags[tag] = commit
			name, version, _ := strings.Cut(tag, "/")
			release, err := virtual.load(name+".md", version, commit, "/"+name+"@"+version)
			if err != nil {
				src := &source{path: name + "/.new-tag", version: "main", record: s.sources[name+"/.new-tag@main"].record}
				virtual.failures = append(virtual.failures, &failure{source: src, line: 2, key: "proposed-file:" + tag, message: err.Error(), phase: virtual.phase})
				continue
			}
			releases = append(releases, release)
		}
		// Evaluate release policy against the complete proposed inventory, so
		// bare/latest dependencies can be released together, in any name order.
		for _, release := range releases {
			virtual.failures = append(virtual.failures, virtual.lintRelease(release)...)
		}
		if err := virtual.walk(); err != nil {
			return nil, err
		}
		// Keep separate phases: a proposed tag must never repair a current error.
		// Do not duplicate failures that are identical before and after tagging.
		current := make(map[string]bool)
		for _, f := range s.failures {
			current[f.signature()] = true
			// With no tags, current latest already checks main, and the
			// redundant future check is omitted. Recognize that same debt
			// if a proposal adds a tag and splits current/future resolution.
			if f.main && strings.HasPrefix(f.key, "current:") {
				current[f.occurrenceKey("future:"+strings.TrimPrefix(f.key, "current:"))] = true
			}
		}
		for _, f := range virtual.failures {
			if !current[f.signature()] {
				s.failures = append(s.failures, f)
			}
		}
		for id, src := range virtual.sources {
			s.sources[id] = src
		}
	}
	return s, nil
}

func (s *snapshot) proposal(p string, data []byte) (string, string, error) {
	name := path.Dir(p)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if !spec.ValidName(name) || len(lines) != 2 || !spec.ValidVersion(strings.TrimSpace(lines[0])) {
		return "", "", fmt.Errorf("invalid .new-tag proposal: expected canonical version and full commit hash on two lines")
	}
	version, commit := strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	if len(commit) != 40 {
		return "", "", fmt.Errorf("invalid .new-tag commit: expected full 40-character commit hash")
	}
	if _, err := hex.DecodeString(commit); err != nil {
		return "", "", fmt.Errorf("invalid .new-tag commit: expected hexadecimal commit hash")
	}
	hash, err := s.repo.commit(commit, s.tip)
	if err != nil {
		return "", "", err
	}
	tag := name + "/" + version
	if _, exists := s.tags[tag]; exists {
		return "", "", fmt.Errorf("proposed tag %s already exists", tag)
	}
	return tag, hash, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func markExisting(base, candidate *snapshot) error {
	old := make(map[string]map[int]bool)
	for _, f := range base.failures {
		key := f.source.id() + "|" + f.phase + "|" + f.key
		if old[key] == nil {
			old[key] = make(map[int]bool)
		}
		old[key][f.line] = true
	}
	maps := make(map[string]map[int]int)
	for _, f := range candidate.failures {
		if f.phase != "" || strings.HasPrefix(f.key, "proposal:") {
			// Release preflight is never grandfathered, including when a
			// proposal or its invalid contents are already committed at HEAD.
			continue
		}
		line := f.line
		if f.source.version == "main" {
			oldSource := base.sources[f.source.id()]
			if oldSource == nil || oldSource.record == nil || f.source.record == nil {
				continue
			}
			mapping, ok := maps[f.source.id()]
			if !ok {
				var err error
				mapping, err = unchangedLines(oldSource.record.data, f.source.record.data)
				if err != nil {
					return err
				}
				maps[f.source.id()] = mapping
			}
			line = mapping[f.line]
			if line == 0 {
				continue
			}
		}
		f.existing = old[f.source.id()+"|"+f.phase+"|"+f.key][line]
	}
	return nil
}
