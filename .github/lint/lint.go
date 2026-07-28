package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"c2sp.org/C2SP/website/spec"
)

func main() {
	paths, err := filepath.Glob("../../*.md")
	if err != nil {
		panic(err)
	}
	failed := false
	for _, path := range paths {
		for _, e := range lintSpec(path) {
			fmt.Printf("%s: %s\n", filepath.Base(path), e)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// lintSpec checks that a spec has a valid name and starts with the front
// matter, warning box, and title heading described in MANUAL.md.
func lintSpec(path string) []string {
	var errs []string
	name := strings.TrimSuffix(filepath.Base(path), ".md")
	if !spec.ValidName(name) {
		errs = append(errs, "invalid spec name")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return append(errs, err.Error())
	}
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	line := func(i int) string {
		if i < len(lines) {
			return lines[i]
		}
		return ""
	}

	if line(0) != "---" {
		return append(errs, "missing front matter")
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if line(i) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return append(errs, "unterminated front matter")
	}
	var desc string
	for i := 1; i < end; i++ {
		if d, ok := strings.CutPrefix(line(i), "description: "); ok {
			desc = d
		}
	}
	switch {
	case desc == "":
		errs = append(errs, "missing front matter description")
	case len(desc) > 100:
		errs = append(errs, "front matter description longer than 100 characters")
	}

	warning := []string{
		"",
		"> [!WARNING]",
		"> This is the editor's copy of this specification.",
		fmt.Sprintf("> For a stable rendered reference, use [c2sp.org/%s](https://c2sp.org/%s).", name, name),
		"",
	}
	for i, want := range warning {
		if got := line(end + 1 + i); got != want {
			errs = append(errs, fmt.Sprintf("line %d: %q, expected %q", end+2+i, got, want))
		}
	}

	if title := line(end + 1 + len(warning)); !strings.HasPrefix(title, "# ") {
		errs = append(errs, "missing title heading after the warning box")
	}
	return errs
}
