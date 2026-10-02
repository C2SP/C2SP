package main

import (
	"bytes"
	"html/template"
	"maps"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"c2sp.org/C2SP/website/document"
	"golang.org/x/net/html"
)

// Inventory actual template output, independently of document's analyzer.
func pageAnchors(t *testing.T, body string) map[string]int {
	t.Helper()
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	anchors := make(map[string]int)
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			seen := make(map[string]bool)
			for _, a := range n.Attr {
				if seen[a.Key] {
					continue
				}
				seen[a.Key] = true
				if a.Key == "id" || n.Data == "a" && a.Key == "name" {
					anchors[a.Val]++
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(root)
	return anchors
}

func TestDocumentHandlerAnchorParity(t *testing.T) {
	repo, _, err := ImportRepo(t.Context(), "testrepo_export.txt", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := handler(repo)
	tests := []struct {
		route, path, ref, spec string
		home                   bool
	}{
		{"/foo@main", "foo.md", "origin/main", "foo", false},
		{"/foo@v2.0.0", "foo.md", "foo/v2.0.0", "foo", false},
		{"/foo@v0.0.1", "foo.md", "foo/v0.0.1", "foo", false},
		{"/", ".github/README.md", "", "", true},
		{"/-/coc", ".github/CODE_OF_CONDUCT.md", "", "", false},
		{"/-/manual", ".github/MANUAL.md", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			src, err := repo.FileAt(tt.path, tt.ref)
			if err != nil {
				t.Fatal(err)
			}
			d, err := document.Render(src, tt.spec, tt.home)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "https://c2sp.org"+tt.route, nil))
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			got := pageAnchors(t, w.Body.String())
			want := make(map[string]int)
			for id := range d.Anchors {
				want[id] = 1
			}
			if !maps.Equal(got, want) {
				t.Errorf("served anchors = %#v, analysis = %#v", got, want)
			}
		})
	}
}

func TestDocumentTemplateAliasParity(t *testing.T) {
	src := `# 雪 &amp; Title

<a id="old"></a>
<a name="older"></a>
<a id="A&amp;雪"></a>

## 雪

[go](#A%26%E9%9B%AA), note[^n].

[^n]: See [old](#old) and $x^2$.
`
	for _, home := range []bool{false, true} {
		for _, spec := range []bool{false, true} {
			d, err := document.Render([]byte(src), "", home)
			if err != nil {
				t.Fatal(err)
			}
			body := d.Body
			if home {
				var index bytes.Buffer
				if err := pageTemplate.ExecuteTemplate(&index, "index", []indexEntry{}); err != nil {
					t.Fatal(err)
				}
				// The real homepage inserts the index above its first H2.
				i := strings.Index(string(body), "<h2")
				body = template.HTML(string(body[:i]) + index.String() + string(body[i:]))
			}
			p := &pageData{
				Title: d.Title, TitleID: d.TitleID, HasTitle: d.HasTitle,
				Home: home, Body: body,
			}
			if spec {
				p.Spec = &specData{Name: "foo", Version: "main"}
			}
			var page bytes.Buffer
			if err := pageTemplate.Execute(&page, p); err != nil {
				t.Fatal(err)
			}
			got := pageAnchors(t, page.String())
			want := make(map[string]int)
			for id := range d.Anchors {
				want[id] = 1
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("home=%v, spec=%v: page %#v, analysis %#v", home, spec, got, want)
			}
		}
	}
}

func TestEmptyAndFallbackTitleTemplate(t *testing.T) {
	for _, src := range []string{"# !!!\n", "No source title.\n"} {
		d, err := document.Render([]byte(src), "", false)
		if err != nil {
			t.Fatal(err)
		}
		p := &pageData{Title: "Fallback", TitleID: d.TitleID, HasTitle: d.HasTitle, Body: d.Body}
		var page bytes.Buffer
		if err := pageTemplate.Execute(&page, p); err != nil {
			t.Fatal(err)
		}
		anchors := pageAnchors(t, page.String())
		_, empty := anchors[""]
		if empty != d.HasTitle {
			t.Errorf("source %q: empty title anchor present=%v, want %v", src, empty, d.HasTitle)
		}
	}
}
