package spec

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// ProjectDocuments maps public document routes to their repository paths.
// The root page additionally includes the generated specification index.
var ProjectDocuments = map[string]string{
	"/":              ".github/README.md",
	"/-/coc":         ".github/CODE_OF_CONDUCT.md",
	"/-/oids":        ".github/OIDs.md",
	"/-/manual":      ".github/MANUAL.md",
	"/-/maintainers": ".github/MAINTAINERS.md",
}

// SpecRedirects contains legacy spec URLs whose fragments survive the redirect.
// Versioned URLs do not inherit these redirects.
var SpecRedirects = map[string]string{
	"/sunlight": "/static-ct-api",
}

// LatestVersion selects the highest stable version, or the highest prerelease
// if there are no stable versions. Empty input selects main (the empty string).
// Unlike semver.Sort, this function does not modify its input.
func LatestVersion(versions []string) string {
	var release, prerelease string
	newer := func(a, b string) bool {
		// Match semver.Sort's lexical tie-break for equivalent versions.
		cmp := semver.Compare(a, b)
		return cmp > 0 || cmp == 0 && a > b
	}
	for _, v := range versions {
		if !semver.IsValid(v) {
			continue
		}
		if semver.Prerelease(v) == "" {
			if newer(v, release) {
				release = v
			}
		} else if newer(v, prerelease) {
			prerelease = v
		}
	}
	if release != "" {
		return release
	}
	return prerelease
}

var commitHashRE = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// ValidCommit reports whether version has the syntax of a commit snapshot.
// Resolution must also check that the commit is reachable from main.
func ValidCommit(version string) bool { return commitHashRE.MatchString(version) }

// Target describes a link to a rendered C2SP document.
type Target struct {
	Path     string // repository path
	Name     string // spec name, or empty for project documents
	Version  string // main, latest, semver, or commit hash
	Fragment string // decoded URL fragment, not a heading to slugify
	Local    bool   // fragment-only reference within the source revision
	Ignore   bool   // external URL or non-document route
}

// ParseLink resolves destination relative to the source's public URL path.
// It classifies the same document routes served by the website; it does not
// check that the spec, version, or fragment exists.
func ParseLink(destination, sourcePath string) (Target, error) {
	u, err := url.Parse(destination)
	if err != nil {
		return Target{}, fmt.Errorf("invalid link %q: %w", destination, err)
	}
	if u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http" {
		return Target{Ignore: true}, nil
	}
	if u.Scheme != "" && u.Host == "" {
		return Target{}, fmt.Errorf("invalid C2SP URL %q: missing host", destination)
	}
	if u.Host != "" && !strings.EqualFold(u.Hostname(), "c2sp.org") {
		return Target{Ignore: true}, nil
	}
	if u.User != nil || (u.Port() != "" && u.Port() != "443" && u.Port() != "80") {
		return Target{}, fmt.Errorf("invalid C2SP URL %q", destination)
	}
	if u.Opaque != "" {
		return Target{}, fmt.Errorf("invalid C2SP URL %q", destination)
	}
	local := u.Host == "" && u.Scheme == "" && u.Path == ""
	base := &url.URL{Scheme: "https", Host: "c2sp.org", Path: sourcePath}
	u = base.ResolveReference(u)
	if u.Query().Get("go-get") == "1" {
		if u.Fragment != "" {
			return Target{}, fmt.Errorf("C2SP go-get metadata URL is not a section destination: %q", destination)
		}
		return Target{Ignore: true}, nil
	}
	t := Target{Fragment: u.Fragment, Local: local}
	path := u.Path
	if path == "" {
		path = "/" // https://c2sp.org and https://c2sp.org/ serve the same page.
	}
	if redirect, ok := SpecRedirects[path]; ok {
		path = redirect
	}
	if file, ok := ProjectDocuments[path]; ok {
		t.Path, t.Version = file, "main"
		return t, nil
	}
	if path == "/CCTV" || strings.HasPrefix(path, "/CCTV/") ||
		strings.HasPrefix(path, "/-/logo/") ||
		strings.HasPrefix(path, "/-/static/") ||
		strings.HasPrefix(path, "/-/math/") || path == "/-/healthz" {
		t.Ignore = true
		return t, nil
	}
	name, version, explicit := strings.Cut(strings.TrimPrefix(path, "/"), "@")
	if !ValidName(name) {
		return Target{}, fmt.Errorf("invalid C2SP document path %q", path)
	}
	if !explicit {
		version = "latest"
	} else if version != "main" && version != "latest" &&
		!semver.IsValid(version) && !ValidCommit(version) {
		return Target{}, fmt.Errorf("invalid C2SP version %q", version)
	}
	t.Path, t.Name, t.Version = name+".md", name, version
	return t, nil
}
