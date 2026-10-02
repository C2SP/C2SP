package speclint

import (
	"fmt"
	"strings"
	"testing"
)

func source(name, body string) string {
	return fmt.Sprintf("---\ndescription: Example spec\n---\n\n"+
		"> [!WARNING]\n> This is the editor's copy of this specification.\n"+
		"> For a stable rendered reference, use [c2sp.org/%s](https://c2sp.org/%s).\n\n%s",
		name, name, body)
}

func TestCheckFormat(t *testing.T) {
	valid := source("example", "# Example\n\n## Section\n\n[section](#section)\n")
	if got := Check("example", []byte(valid)); len(got) != 0 {
		t.Fatalf("valid specification: %+v", got)
	}
	tests := []struct {
		name, src, want string
		line            int
	}{
		{"bad_name", valid, "invalid spec name", 1},
		{"example", "# Example\n", "missing front matter", 1},
		{"example", "---\ndescription: Example\n", "unterminated front matter", 1},
		{"example", strings.Replace(valid, "description: Example spec", "unknown: Example", 1), "missing front matter description", 1},
		{"example", strings.Replace(valid, "Example spec", strings.Repeat("x", 101), 1), "longer than 100", 2},
		{"example", strings.Replace(valid, "Example spec", "Example spec.", 1), "should not end with a period", 2},
		{"example", strings.Replace(valid, "> [!WARNING]", "> [!NOTE]", 1), `expected "> [!WARNING]"`, 5},
		{"example", strings.Replace(valid, "# Example\n", "Example\n", 1), "missing title heading", 9},
		{"example", source("example", "# Example\n\n[missing][]\n"), "undefined Markdown reference", 11},
		{"example", source("example", "# Example\n\n[^missing]\n"), "undefined footnote reference", 11},
		{"example", source("example", "# Example\n\n[spec](https://github.com/C2SP/C2SP/blob/main/example.md)\n"), "link to GitHub instead", 11},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := Check(tt.name, []byte(tt.src))
			for _, p := range got {
				if strings.Contains(p.Message, tt.want) && p.Line == tt.line {
					return
				}
			}
			t.Fatalf("missing %q on line %d: %+v", tt.want, tt.line, got)
		})
	}
}

func TestNormalLintAllowsDevelopmentMarkersAndTasks(t *testing.T) {
	got := Check("example", []byte(source("example", "# Example\n\nTODO TK TBD FIXME\n\n- [ ] Pending\n")))
	if len(got) != 0 {
		t.Fatalf("normal source lint imposed release policy: %+v", got)
	}
}

func TestLintMath(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		invalid bool
	}{
		{name: "valid inline", body: "# Test\n\n$x^2$\n"},
		{name: "valid display", body: "# Test\n\n```math\nx^2\n```\n"},
		{name: "invalid inline", body: "# Test\n\n$\\frac{$\n", invalid: true},
		{name: "invalid display", body: "# Test\n\n```math\n\\frac{\n```\n", invalid: true},
		{name: "invalid TeX in code", body: "# Test\n\n`$\\frac{$`\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errs := Body([]byte(test.body))
			found := false
			for _, err := range errs {
				if strings.HasPrefix(err.Message, "invalid mathematical expression:") {
					found = true
				}
			}
			if found != test.invalid {
				t.Fatalf("invalid math error = %v, want %v; errors: %v", found, test.invalid, errs)
			}
		})
	}
}
