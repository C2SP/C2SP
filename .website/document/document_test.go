package document

import (
	"bytes"
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/yuin/goldmark/text"
)

func render(t *testing.T, src string, spec string, home bool) *Document {
	t.Helper()
	d, err := Render([]byte(src), spec, home)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRenderedAnalysis(t *testing.T) {
	src := strings.Join([]string{
		"---", // 1
		"description: Shared document analysis",
		"---",
		"> [!WARNING]",
		`> See https://c2sp.org/foo. <a id="removed-warning" href="#removed-warning"></a>`,
		"",
		`# Foo [removed title link](#missing) <a id="removed-title"></a>`,
		"",
		"[c2sp.org/foo](https://c2sp.org/foo#removed-url)",
		"",
		`<a id="old-name"></a>`, // 11
		`<a name='even-older'></a>`,
		"",
		"## New Section", // 14
		"",
		"[reference][ref]", // 16
		"",
		"[ref]: https://c2sp.org/foo#new-section",
		"[unused]: https://c2sp.org/foo#unused",
		"",
		"<div", // 21
		` id="A&amp;雪">`,
		`<a href="https://c2sp.org/foo#A%26%E9%9B%AA">HTML</a>`, // 23
		"</div>",
		"",
		"`<a id=\"inline-code\" href=\"#inline-code\"></a>`",
		"",
		"```html",
		`<a id="fenced-code" href="#fenced-code"></a>`,
		"```",
		"",
		`<!-- <a id="comment" href="#comment"></a> -->`,
		"",
		`<script>var x = '<a id="script" href="#script"></a>';</script>`,
		"",
		"<https://c2sp.org/foo#new-section>", // 36
		"",
		"",
	}, "\n")
	d := render(t, src, "foo", false)
	if d.TitleID != "foo-removed-title-link-" || !d.HasTitle {
		t.Fatalf("title: %q, id: %q, present: %v", d.Title, d.TitleID, d.HasTitle)
	}
	want := map[string]int{
		d.TitleID:     7,
		"old-name":    11,
		"even-older":  12,
		"new-section": 14,
		"A&雪":         22,
	}
	if !maps.Equal(d.Anchors, want) {
		t.Errorf("anchors = %#v, want %#v", d.Anchors, want)
	}
	wantLinks := []Link{
		{"#new-section", 14},
		{"https://c2sp.org/foo#new-section", 16},
		{"https://c2sp.org/foo#A%26%E9%9B%AA", 23},
		{"https://c2sp.org/foo#new-section", 36},
	}
	if !reflect.DeepEqual(d.Links, wantLinks) {
		t.Errorf("links = %#v, want %#v", d.Links, wantLinks)
	}
	if len(d.Problems) > 0 {
		t.Errorf("problems = %#v", d.Problems)
	}
	if d.Description != "Shared document analysis" {
		t.Errorf("description = %q", d.Description)
	}
}

func TestAliasesAndCollisions(t *testing.T) {
	src := `# Title

<a id="old"></a>
<a id="older"></a>
<a name="oldest"></a>

## New

<a id="new"></a>
<a name="old"></a>
<span id=""></span>
<a name=""></a>
<a id="title"></a>

## Dup

## Dup

## Dup-1

## !!!

<div id="x" id="ignored-second-attribute"></div>
`
	d := render(t, src, "", false)
	want := []Problem{
		{9, `duplicate rendered anchor "new" (first defined on line 7)`},
		{10, `duplicate rendered anchor "old" (first defined on line 3)`},
		{11, "empty rendered anchor"},
		{12, "empty rendered anchor"},
		{12, `duplicate rendered anchor "" (first defined on line 11)`},
		{13, `duplicate rendered anchor "title" (first defined on line 1)`},
		{19, `duplicate rendered anchor "dup-1" (first defined on line 17)`},
		{21, "empty rendered anchor"},
		{21, `duplicate rendered anchor "" (first defined on line 11)`},
	}
	if !reflect.DeepEqual(d.Problems, want) {
		t.Errorf("problems = %#v, want %#v", d.Problems, want)
	}
	for _, id := range []string{"old", "older", "oldest", "new", "title", "dup", "dup-1", "x"} {
		if _, ok := d.Anchors[id]; !ok {
			t.Errorf("missing anchor %q", id)
		}
	}
	if _, ok := d.Anchors["ignored-second-attribute"]; ok {
		t.Error("accepted an ignored duplicate HTML attribute")
	}
	if !strings.Contains(string(d.Body), `<h2 id="new">`) {
		t.Error("aliases changed generated heading IDs")
	}
}

func TestTitleAndHomepage(t *testing.T) {
	d := render(t, "# Title\n\n## Title\n", "", false)
	if d.TitleID != "title" || d.Anchors["title"] != 1 || d.Anchors["title-1"] != 3 {
		t.Fatalf("title/dedup: %#v", d)
	}
	d = render(t, "# !!!\n", "", false)
	if !d.HasTitle || len(d.Problems) != 1 || d.Problems[0].Line != 1 {
		t.Fatalf("empty title ID: %#v", d)
	}
	d = render(t, "No title.\n", "", false)
	if d.HasTitle || len(d.Anchors) != 0 {
		t.Fatalf("fabricated title anchor: %#v", d)
	}
	d = render(t, `<p id="logo"><img src="/.logo/logo.svg"><a href="#missing">logo</a></p>

# Project

<a id="specifications"></a>

## Specifications
`, "", true)
	if _, ok := d.Anchors["logo"]; ok {
		t.Fatal("accepted removed logo anchor")
	}
	if d.Anchors["specifications"] != 0 || len(d.Problems) != 2 ||
		d.Problems[0].Line != 5 || d.Problems[1].Line != 7 {
		t.Errorf("homepage collisions: anchors %#v, problems %#v", d.Anchors, d.Problems)
	}
	for _, link := range d.Links {
		if link.Destination == "#missing" {
			t.Fatal("accepted removed logo link")
		}
	}
}

func TestFootnotes(t *testing.T) {
	src := "# Notes\n\nA note[^n].\n\n[^n]: Footnote with a [reference][r].\n\n[r]: #notes\n"
	d := render(t, src, "", false)
	want := map[string]int{"notes": 1, "fnref:1": 3, "fn:1": 5}
	if !maps.Equal(d.Anchors, want) {
		t.Errorf("anchors = %#v, want %#v", d.Anchors, want)
	}
	wantLinks := []Link{{"#fn:1", 3}, {"#notes", 5}, {"#fnref:1", 5}}
	if !reflect.DeepEqual(d.Links, wantLinks) {
		t.Errorf("links = %#v, want %#v", d.Links, wantLinks)
	}
	d = render(t, src+"\n<a id='fn:1'></a>\n", "", false)
	if len(d.Problems) != 1 || !strings.Contains(d.Problems[0].Message, `"fn:1"`) {
		t.Errorf("footnote collision = %#v", d.Problems)
	}
}

func TestEntityUnicodeAndRawHTML(t *testing.T) {
	d := render(t, `# 雪 &amp; Ice

## 雪

<a id="A&amp;雪" name="legacy&#x96ea;" href="#A%26%E9%9B%AA">link</a>
<div id="Case+Sensitive"></div>
<a href="#Case+Sensitive">plus</a>

<td id="discarded" >invalid table cell</td>

<head id="discarded-head"></head>
`, "", false)
	for _, id := range []string{d.TitleID, "雪", "A&雪", "legacy雪", "Case+Sensitive"} {
		if _, ok := d.Anchors[id]; !ok {
			t.Errorf("missing %q: %#v", id, d.Anchors)
		}
	}
	if _, ok := d.Anchors["discarded"]; ok {
		t.Error("accepted HTML discarded by the browser parser")
	}
	if _, ok := d.Anchors["discarded-head"]; ok {
		t.Error("accepted HEAD discarded inside the page's MAIN")
	}
	// Unicode permalinks are emitted directly by the existing renderer.
	if !reflect.DeepEqual(d.Links, []Link{{"#雪", 3}, {"#A%26%E9%9B%AA", 5}, {"#Case+Sensitive", 7}}) {
		t.Errorf("links = %#v", d.Links)
	}
}

func TestMathAndRenderingParity(t *testing.T) {
	src := []byte("# Math $x^2$\n\n## Equation $x^2$\n\n$\\frac{<script>$\n\n```math\nx + y\n```\n")
	d, err := Render(src, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMath(src); err == nil {
		t.Error("strict math validation accepted an invalid expression")
	}
	if err := ValidateMath([]byte("$x^2$\n")); err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(d.Body), `class="math-error"`) ||
		strings.Contains(string(d.Body), "<script>") {
		t.Errorf("tolerant math fallback = %s", d.Body)
	}
	// Source mapping wraps all renderers, but must not change their output.
	md := NewMarkdown()
	ast := md.Parser().Parse(text.NewReader(src))
	transformAlerts(ast, src)
	addHeadingIDs(ast, src)
	ast.RemoveChild(ast, firstH1(ast))
	var plain bytes.Buffer
	if err := md.Renderer().Render(&plain, src, ast); err != nil {
		t.Fatal(err)
	}
	if plain.String() != string(d.Body) {
		t.Errorf("mapped rendering differs:\n%s\nplain:\n%s", d.Body, plain.String())
	}
	// Preserve existing slug behavior: math nodes contribute no plain text.
	if d.TitleID != "math-" || d.Anchors["equation-"] != 3 {
		t.Errorf("math heading IDs = %#v", d.Anchors)
	}
}

func TestReferenceOccurrencePositions(t *testing.T) {
	src := "# Links\n\n[ref][r]\n[ref][r]\n\n[\nmultiline\n][r]\n\n[r]: #links\n\n[empty][]\n\n[empty]: #links\n"
	d := render(t, src, "", false)
	want := []Link{{"#links", 3}, {"#links", 4}, {"#links", 6}, {"#links", 12}}
	if !reflect.DeepEqual(d.Links, want) {
		t.Errorf("links = %#v, want %#v", d.Links, want)
	}
}

func TestAdjacentGeneratedAndEmptyLinkPositions(t *testing.T) {
	src := "# Links\n\n[^n]\n[^n]\n\n[^n]: note\n\n<https://c2sp.org/foo#links>\n<https://c2sp.org/foo#links>\n\n[](#links)\n[](#links)\n"
	d := render(t, src, "", false)
	want := []Link{
		{"#fn:1", 3}, {"#fn:1", 4},
		{"https://c2sp.org/foo#links", 8}, {"https://c2sp.org/foo#links", 9},
		{"#links", 11}, {"#links", 12},
		{"#fnref:1", 6}, {"#fnref1:1", 6},
	}
	if !reflect.DeepEqual(d.Links, want) {
		t.Errorf("links = %#v, want %#v\n%s", d.Links, want, d.Body)
	}
}

func TestForeignHTMLPositions(t *testing.T) {
	d := render(t, "# SVG\n\n<svg viewBox='0 0 10 10'>\n<linearGradient id='gradient'></linearGradient>\n<a href='#gradient' xlink:href='#gradient'>link</a>\n</svg>\n", "", false)
	if d.Anchors["gradient"] != 4 ||
		!reflect.DeepEqual(d.Links, []Link{{"#gradient", 5}}) {
		t.Errorf("foreign HTML: anchors %#v, links %#v", d.Anchors, d.Links)
	}
}

func TestMultilineHTMLAttributePositions(t *testing.T) {
	d := render(t, `# HTML

<a
 title='a fake href="#ignore" and id="ignore"'
 ID="alias"
 href="#html">link</a>

<a
 name='legacy'
 HREF=#alias>legacy link</a>
`, "", false)
	if d.Anchors["alias"] != 5 || d.Anchors["legacy"] != 9 ||
		!reflect.DeepEqual(d.Links, []Link{{"#html", 6}, {"#alias", 10}}) {
		t.Errorf("multiline HTML: anchors %#v, links %#v", d.Anchors, d.Links)
	}
	for _, link := range d.Links {
		if link.Destination == "#ignore" {
			t.Error("accepted quoted fake href")
		}
	}
}

func TestSameElementIDAndName(t *testing.T) {
	d := render(t, "# Title\n\n<a id='alias' name='alias'></a>\n", "", false)
	if len(d.Problems) != 0 || d.Anchors["alias"] != 3 {
		t.Fatalf("same-element aliases: anchors %#v, problems %#v", d.Anchors, d.Problems)
	}
	d = render(t, "# Title\n\n<a name='alias' id='alias'></a>\n<a name='alias'></a>\n", "", false)
	if !reflect.DeepEqual(d.Problems, []Problem{
		{4, `duplicate rendered anchor "alias" (first defined on line 3)`},
	}) {
		t.Errorf("distinct-element collision: %#v", d.Problems)
	}
}

func TestInertTemplateContents(t *testing.T) {
	d := render(t, `# Title

<template id="template">
<a id="inert" name="inert-name" href="#missing">inert</a>
<template><a id="nested-inert" href="#nested-missing"></a></template>
<a id="live" href="#title">live</a>
</template>

<a id="live" href="#title">live</a>
`, "", false)
	if !maps.Equal(d.Anchors, map[string]int{"title": 1, "template": 3, "live": 9}) ||
		!reflect.DeepEqual(d.Links, []Link{{"#title", 9}}) || len(d.Problems) != 0 {
		t.Errorf("templates: anchors %#v, links %#v, problems %#v", d.Anchors, d.Links, d.Problems)
	}
}

func TestRejectBaseURL(t *testing.T) {
	d := render(t, "# Title\n\n<base href='https://c2sp.org/other@v1.0.0'>\n\n[own](#title)\n", "", false)
	if len(d.Problems) != 1 || d.Problems[0].Line != 3 ||
		!strings.Contains(d.Problems[0].Message, "<base href>") {
		t.Fatalf("base URL was not rejected: %#v", d.Problems)
	}
	d = render(t, "# Title\n\n```html\n<base href='https://example.com'>\n```\n\n<template><base href='https://example.com'></template>\n", "", false)
	if len(d.Problems) != 0 {
		t.Fatalf("inert base URL rejected: %#v", d.Problems)
	}
}
