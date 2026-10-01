package document

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestUndefinedReferences(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Problem
	}{
		{
			"explicit collapsed images and footnotes",
			"[text][missing] [collapsed][] ![alt][image] ![collapsed image][] [^note]",
			[]Problem{
				{1, `undefined Markdown reference "missing"`},
				{1, `undefined Markdown reference "collapsed"`},
				{1, `undefined Markdown reference "image"`},
				{1, `undefined Markdown reference "collapsed image"`},
				{1, `undefined footnote reference "note"`},
			},
		},
		{
			"original lines and front matter",
			"---\r\ndescription: '[not][a-reference]'\r\n---\r\n# [title][missing]\r\n\r\n> ![image\r\n> label][unknown]\r\n\r\n- [^footnote]\r\n",
			[]Problem{
				{4, `undefined Markdown reference "missing"`},
				{6, `undefined Markdown reference "unknown"`},
				{9, `undefined footnote reference "footnote"`},
			},
		},
		{
			"invalid YAML still skipped",
			"---\ndescription: [\n---\n[x][missing]",
			[]Problem{{4, `undefined Markdown reference "missing"`}},
		},
		{
			"multiline reference label and collapsed text",
			"[label][ multi\n line ]\n[collapsed\n text][]",
			[]Problem{
				{1, `undefined Markdown reference "multi line"`},
				{3, `undefined Markdown reference "collapsed text"`},
			},
		},
		{
			"multiline quote reference",
			"> [text][not\n> defined]\n",
			[]Problem{{1, `undefined Markdown reference "not defined"`}},
		},
		{
			"formatted labels",
			"[**bold** and `code`][missing]\n[*emphasis*][]\n[`code`][]\n![*image*][]",
			[]Problem{
				{1, `undefined Markdown reference "missing"`},
				{2, `undefined Markdown reference "*emphasis*"`},
				{3, "undefined Markdown reference \"`code`\""},
				{4, `undefined Markdown reference "*image*"`},
			},
		},
		{
			"nested brackets in label",
			"[text [array] text][missing]",
			[]Problem{{1, `undefined Markdown reference "missing"`}},
		},
		{
			"brackets inside formatted code label",
			"[`[a][b]` and **text**][missing]",
			[]Problem{{1, `undefined Markdown reference "missing"`}},
		},
		{
			"forward definitions ordinary normalization",
			"[text][  FOO\tbar ] [Straße][] ![alt][STRASSE] [*formatted*][] [`code`][]\n\n[foo bar]: /url\n[strasse]: /url\n[*formatted*]: /url\n[`code`]: /url",
			nil,
		},
		{
			"escaped labels match raw Goldmark spelling",
			"[x][a\\*b] [x][a\\]b] [a\\*b][]\n\n[a\\*b]: /url\n[a\\]b]: /url",
			nil,
		},
		{
			"escapes are not silently removed from labels",
			"[x][a\\*b]\n\n[a*b]: /url",
			[]Problem{{1, `undefined Markdown reference "a\\*b"`}},
		},
		{
			"forward footnotes and nested reference in footnotes",
			"[^note] [^next]\n\n[^note]: [*nested*][ref] and [^next]\n[^next]: note\n\n[ref]: /url",
			nil,
		},
		{
			"footnotes use exact case whitespace and escapes",
			"[^Case] [^two  spaces] [^a\\*b]\n\n[^Case]: note\n[^two  spaces]: note\n[^a\\*b]: note",
			nil,
		},
		{
			"footnote mismatch is not ordinary reference normalization",
			"[^case] [^two spaces] [^a*b]\n\n[^Case]: note\n[^two  spaces]: note\n[^a\\*b]: note",
			[]Problem{
				{1, `undefined footnote reference "case"`},
				{1, `undefined footnote reference "two spaces"`},
				{1, `undefined footnote reference "a*b"`},
			},
		},
		{
			"undefined inside used and unused footnotes",
			"[^used]\n\n[^used]: [x][missing] [^absent]\n[^unused]: [x][also missing]",
			[]Problem{
				{3, `undefined Markdown reference "missing"`},
				{3, `undefined footnote reference "absent"`},
				{4, `undefined Markdown reference "also missing"`},
			},
		},
		{
			"unused definitions and definition titles",
			"[unused]: /url \"[x][missing] [^note]\"\n[other]: https://example.com/[x][y]\n\n[^unused]: Plain prose.",
			nil,
		},
		{
			"ordinary inline links destinations titles images and autolinks",
			"[text](/path \"[a][b] [^note]\") ![alt](/path '[a][b]')\n[<https://example.com> [^valid]](/path)\n<https://example.com/[a][b]>\n\n[^valid]: note",
			nil,
		},
		{
			"inline links with reference labels",
			"[outer ![inner][ref]](/path \"title [a][b]\") [outer [array]](/path)\n\n[ref]: /url",
			nil,
		},
		{
			"code blocks and spans",
			"`[text][missing] [^note]` ``[x][y] `[^n]` ``\n\n```markdown\n[x][y] [^n]\n```\n\n~~~\n[x][y]\n~~~\n\n    [x][y] [^n]\n",
			nil,
		},
		{
			"HTML blocks tags comments",
			"<div>\n[x][y] [^n]\n</div>\n\nText <span title='[x][y] [^n]'>ok</span> <!-- [x][y] [^n] -->\n\n<!--\n[x][y] [^n]\n-->\n\n<script>\n[x][y] [^n]\n</script>",
			nil,
		},
		{
			"math",
			"$[x][y] + [^n]$ and $$[x][y]$$ and $`[x][y]`$\n\n$$\n[x][y] [^n]\n$$\n\n```math\n[x][y] [^n]\n```",
			nil,
		},
		{
			"escaped literal brackets",
			"\\[text][missing] [text]\\[missing] \\[^note] [text\\][missing]\n\\![alt][missing]",
			// Escaping ! does not escape the link's opening bracket.
			[]Problem{{2, `undefined Markdown reference "missing"`}},
		},
		{
			"escaped closing bracket",
			"[text\\]][missing]",
			[]Problem{{1, `undefined Markdown reference "missing"`}},
		},
		{
			"conservative shortcuts prose and alerts",
			"[array] [undefined shortcut] ![undefined image shortcut] [foo](invalid link)\n\n> [!WARNING]\n> [array]\n",
			nil,
		},
		{
			"GFM task lists remain allowed",
			"- [ ] Pending task\n- [x] Complete task\n- [X] Another complete task\n",
			nil,
		},
		{
			"references inside GFM task lists",
			"- [ ] [label][missing]\n- [x] [missing][]\n- [ ] [^absent]\n",
			[]Problem{
				{1, `undefined Markdown reference "missing"`},
				{2, `undefined Markdown reference "missing"`},
				{3, `undefined footnote reference "absent"`},
			},
		},
		{
			"table cells",
			"| Label | Notes |\n| --- | --- |\n| [x][missing] | [^note] |\n| [array] | `[^code]` |",
			[]Problem{
				{3, `undefined Markdown reference "missing"`},
				{3, `undefined footnote reference "note"`},
			},
		},
		{
			"block markers reset",
			"[unclosed\n\n[x][missing]",
			[]Problem{{3, `undefined Markdown reference "missing"`}},
		},
		{
			"unterminated and invalid reference syntax",
			"[array]\n[another array]\n\n[open][\n\n[^]\n\n[x][nested [label]]",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UndefinedReferences([]byte(tt.src)); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("UndefinedReferences:\n got %#v\nwant %#v", got, tt.want)
			}
			assertReferenceHooksPreserveParsing(t, []byte(tt.src))
		})
	}
}

// The observers must not change parser state, delimiter handling, reader
// positions, or rendered output, including when a parser returns nil and the
// next parser retries the same punctuation.
func assertReferenceHooksPreserveParsing(t *testing.T, src []byte) {
	t.Helper()
	_, body, _ := SplitFrontMatter(src)
	plain, checked := NewMarkdown(), NewMarkdown()
	checked.Parser().AddOptions(&referenceCheck{source: body})
	var want, got bytes.Buffer
	if err := plain.Convert(body, &want); err != nil {
		t.Fatal(err)
	}
	if err := checked.Convert(body, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("reference hooks changed parsing:\n got %s\nwant %s", &got, &want)
	}
}

func TestUndefinedReferencesLabelLimit(t *testing.T) {
	// Invalid overlong labels are not reference links in Goldmark.
	src := "[x][" + strings.Repeat("a", 1000) + "]"
	if got := UndefinedReferences([]byte(src)); len(got) != 0 {
		t.Fatalf("invalid reference label reported: %v", got)
	}
}
