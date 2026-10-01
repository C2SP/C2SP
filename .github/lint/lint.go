package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"c2sp.org/C2SP/.github/linkcheck"
	"c2sp.org/C2SP/.github/speclint"
)

func main() {
	root := flag.String("root", "", "repository root (default: current Git repository)")
	base := flag.String("base", "", "base commit for regression checks (default: full audit)")
	linksOnly := flag.Bool("links-only", false, "skip working-tree specification source checks")
	annotations := flag.Bool("github-actions", os.Getenv("GITHUB_ACTIONS") == "true", "emit GitHub Actions annotations")
	flag.Parse()
	if *root == "" {
		out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, "lint: locate repository:", err)
			os.Exit(1)
		}
		*root = strings.TrimSpace(string(out))
	}
	paths, err := filepath.Glob(filepath.Join(*root, "*.md"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "lint:", err)
		os.Exit(1)
	}
	failed := false
	if !*linksOnly {
		for _, path := range paths {
			for _, e := range lintSpec(path) {
				printDiagnostic(os.Stdout, linkcheck.Diagnostic{
					File: filepath.Base(path), Line: e.Line, Message: e.Message,
				}, *annotations)
				failed = true
			}
		}
	}
	diagnostics, err := linkcheck.Check(*root, *base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lint:", err)
		os.Exit(1)
	}
	for _, d := range diagnostics {
		printDiagnostic(os.Stdout, d, *annotations)
		failed = failed || !d.Existing
	}
	if failed {
		os.Exit(1)
	}
}

func printDiagnostic(w io.Writer, d linkcheck.Diagnostic, annotations bool) {
	location := d.File
	if d.Line > 0 {
		location += fmt.Sprintf(":%d", d.Line)
	}
	if d.Existing {
		// Prefix continuation lines too, so an ID containing a newline cannot
		// inject a workflow command while reporting pre-existing debt.
		message := strings.ReplaceAll(d.Message, "\r", "\\r")
		message = strings.ReplaceAll(message, "\n", "\n  ")
		location = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(location)
		fmt.Fprintf(w, "existing: %s: %s\n", location, message)
		return
	}
	if !annotations {
		fmt.Fprintf(w, "%s: %s\n", location, d.Message)
		return
	}
	// Escape workflow command data, including untrusted Markdown and file names.
	escape := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	propertyEscape := strings.NewReplacer(":", "%3A", ",", "%2C")
	properties := ""
	if d.File != "" {
		properties = " file=" + propertyEscape.Replace(escape.Replace(d.File))
		if d.Line > 0 {
			properties += fmt.Sprintf(",line=%d", d.Line)
		}
	}
	fmt.Fprintf(w, "::error%s::%s\n", properties, escape.Replace(d.Message))
}

// lintSpec loads a working-tree specification before applying the shared lints.
func lintSpec(path string) []speclint.Problem {
	info, err := os.Lstat(path)
	if err != nil {
		return []speclint.Problem{{Line: 1, Message: err.Error()}}
	}
	if !info.Mode().IsRegular() {
		return []speclint.Problem{{Line: 1, Message: "specification must be a regular file, not a symlink"}}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []speclint.Problem{{Line: 1, Message: err.Error()}}
	}
	return speclint.Check(strings.TrimSuffix(filepath.Base(path), ".md"), data)
}
