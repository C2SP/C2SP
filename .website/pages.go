package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"c2sp.org/C2SP/website/spec"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

var pageTemplate = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// site renders the c2sp.org pages from the repository mirror.
type site struct {
	repo  *Repo
	cache pageCache
}

type pageData struct {
	TabTitle    string
	Title       string
	Description string
	Home        bool
	Spec        *specData
	Index       []indexEntry
	Body        template.HTML
}

type specData struct {
	Name        string
	Version     string   // "v1.0.0", "main", or a commit hash
	Date        string   // committer date of the rendered version
	Notice      string   // "", "development", or "snapshot"
	Latest      string   // latest release, shown in the notice
	Versions    []string // tagged versions, newest first
	Maintainers []string
	SourceURL   string
	IssueURL    string
}

type indexEntry struct {
	Name        string
	Description string
}

func (s *site) serveSpec(w http.ResponseWriter, r *http.Request) {
	name, vers, ok := strings.Cut(r.PathValue("name"), "@")
	if !ok {
		vers = "latest"
	}
	if !spec.ValidName(name) {
		http.Error(w, "invalid spec name", http.StatusBadRequest)
		return
	}

	gen := s.repo.Generation()
	if page, ok := s.cache.get(r.URL.Path, gen); ok && !wantsMarkdown(r) {
		writePage(w, page)
		return
	}

	versions, err := s.repo.Versions(name)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get versions: %v", err), http.StatusInternalServerError)
		return
	}
	latest := latestVersion(versions)

	if vers == "latest" {
		vers = latest
		if vers == "" {
			vers = "main"
		}
	}

	// ref is the git ref to render, blobRef the GitHub URL version of it.
	var ref, blobRef, notice string
	switch {
	case vers == "main":
		ref, blobRef = "origin/main", "main"
		notice = "development"
	case slices.Contains(versions, vers):
		ref, blobRef = name+"/"+vers, name+"/"+vers
	case s.repo.IsCommit(vers):
		ref, blobRef = vers, vers
		notice = "snapshot"
	default:
		http.Error(w, "version not found", http.StatusNotFound)
		return
	}

	src, err := s.repo.FileAt(name+".md", ref)
	if err != nil {
		http.Error(w, "spec not found", http.StatusNotFound)
		return
	}

	if wantsMarkdown(r) {
		writeMarkdown(w, markdownSource(src, name))
		return
	}

	doc, err := renderMarkdown(src, name, false)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to render spec: %v", err), http.StatusInternalServerError)
		return
	}
	title := doc.Title
	if title == "" {
		title = name
	}

	var date string
	if t, err := s.repo.CommitTime(ref); err == nil {
		date = t.Format("2006-01-02")
	}

	var maintainers []string
	if md, err := s.repo.FileAt(".github/MAINTAINERS.md", ""); err == nil {
		maintainers = parseMaintainers(md, name)
	}

	newestFirst := slices.Clone(versions)
	slices.Reverse(newestFirst)

	sd := &specData{
		Name:        name,
		Version:     vers,
		Date:        date,
		Notice:      notice,
		Versions:    newestFirst,
		Maintainers: maintainers,
		SourceURL:   "https://github.com/C2SP/C2SP/blob/" + blobRef + "/" + name + ".md",
		// Spec names are URL-safe, and "%3A%20" is ": ".
		IssueURL: "https://github.com/C2SP/C2SP/issues/new?title=" + name + "%3A%20",
	}
	if notice != "" {
		sd.Latest = latest
	}
	s.servePage(w, r, gen, &pageData{
		TabTitle:    title + " | C2SP",
		Title:       title,
		Description: doc.Description,
		Spec:        sd,
		Body:        doc.Body,
	})
}

func (s *site) serveIndex(w http.ResponseWriter, r *http.Request) {
	gen := s.repo.Generation()
	if page, ok := s.cache.get(r.URL.Path, gen); ok && !wantsMarkdown(r) {
		writePage(w, page)
		return
	}

	readme, err := s.repo.FileAt(".github/README.md", "")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get README: %v", err), http.StatusInternalServerError)
		return
	}

	if wantsMarkdown(r) {
		writeMarkdown(w, markdownSource(readme, ""))
		return
	}

	doc, err := renderMarkdown(readme, "", true)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to render README: %v", err), http.StatusInternalServerError)
		return
	}

	specs, err := s.repo.Specs()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list specs: %v", err), http.StatusInternalServerError)
		return
	}
	var index []indexEntry
	for _, name := range specs {
		src, err := s.repo.FileAt(name+".md", "")
		if err != nil {
			continue
		}
		fm, _, _ := splitFrontMatter(src)
		index = append(index, indexEntry{Name: name, Description: fm.Description})
	}

	title := doc.Title
	if title == "" {
		title = "The Community Cryptography Specification Project"
	}
	s.servePage(w, r, gen, &pageData{
		TabTitle: "C2SP — " + title,
		Title:    title,
		Home:     true,
		Index:    index,
		Body:     doc.Body,
	})
}

// docHandler returns a handler that renders a project document, such as the
// Code of Conduct, from origin/main.
func (s *site) docHandler(path, fallbackTitle string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gen := s.repo.Generation()
		if page, ok := s.cache.get(r.URL.Path, gen); ok && !wantsMarkdown(r) {
			writePage(w, page)
			return
		}
		src, err := s.repo.FileAt(path, "")
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if wantsMarkdown(r) {
			writeMarkdown(w, markdownSource(src, ""))
			return
		}

		doc, err := renderMarkdown(src, "", false)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to render document: %v", err), http.StatusInternalServerError)
			return
		}
		title := doc.Title
		if title == "" {
			title = fallbackTitle
		}
		s.servePage(w, r, gen, &pageData{
			TabTitle: title + " | C2SP",
			Title:    title,
			Body:     doc.Body,
		})
	}
}

var logoFileRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`)

func (s *site) serveLogo(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	var contentType string
	switch {
	case strings.HasSuffix(file, ".svg"):
		contentType = "image/svg+xml"
	case strings.HasSuffix(file, ".png"):
		contentType = "image/png"
	default:
		http.NotFound(w, r)
		return
	}
	if !logoFileRE.MatchString(file) {
		http.NotFound(w, r)
		return
	}
	data, err := s.repo.FileAt(".logo/"+file, "")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// servePage renders the page template, caching the result under the request
// path.
func (s *site) servePage(w http.ResponseWriter, r *http.Request, gen uint64, data *pageData) {
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		log.Printf("failed to execute template: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.cache.put(r.URL.Path, gen, buf.Bytes())
	writePage(w, buf.Bytes())
}

func writePage(w http.ResponseWriter, page []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Vary", "Accept")
	w.Write(page)
}

// wantsMarkdown reports whether the request prefers the Markdown source over
// the rendered HTML. Browsers don't list text/markdown in Accept headers.
func wantsMarkdown(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/markdown")
}

func writeMarkdown(w http.ResponseWriter, src []byte) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Vary", "Accept")
	w.Write(src)
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.StripPrefix("/-/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxAge := "3600"
		if strings.HasPrefix(r.URL.Path, "/-/static/fonts/") {
			maxAge = "604800"
		}
		w.Header().Set("Cache-Control", "public, max-age="+maxAge)
		fileServer.ServeHTTP(w, r)
	})
}
