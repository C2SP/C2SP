package linkcheck

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type repository struct {
	root  string
	cache map[string]*record
}

// inputError is not a broken link: unsafe working-tree inputs must stop the
// checker, rather than masquerading as missing files or being grandfathered.
type inputError struct{ err error }

func (e *inputError) Error() string { return e.err.Error() }
func (e *inputError) Unwrap() error { return e.err }

func invalidInput(err error) bool {
	var input *inputError
	return errors.As(err, &input)
}

func (r *repository) requireFullClone() error {
	// Older Git versions do not honor GIT_NO_LAZY_FETCH. Inspect effective
	// configuration before fsck, rev-parse, or any other object access.
	config, err := r.git("config", "--list", "--null")
	if err != nil {
		return err
	}
	for entry := range strings.SplitSeq(string(config), "\x00") {
		key, value, hasValue := strings.Cut(entry, "\n")
		key = strings.ToLower(key)
		promisor := strings.HasPrefix(key, "remote.") && strings.HasSuffix(key, ".promisor")
		// A valueless boolean is true; empty values and explicit false values
		// are false. Conservatively reject unrecognized boolean values too.
		value = strings.ToLower(strings.TrimSpace(value))
		truthy := !hasValue || (value != "" && value != "false" && value != "no" && value != "off" && value != "0")
		if key == "extensions.partialclone" || (promisor && truthy) {
			return fmt.Errorf("section link checking requires a full clone; partial/promisor repositories are unsupported (%s)", key)
		}
	}
	return nil
}

func (r *repository) git(args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", r.root}, args...)...)
	// Defense in depth; requireFullClone rejects partial clones even on Git
	// versions that do not understand GIT_NO_LAZY_FETCH.
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (r *repository) read(ref, path string) ([]byte, error) {
	if ref == "" {
		if err := r.regularWorkingFile(path); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(filepath.Join(r.root, filepath.FromSlash(path)))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, &inputError{fmt.Errorf("cannot read working-tree source %s: %w", path, err)}
		}
		return data, err
	}
	return r.git("show", "--end-of-options", ref+":"+path)
}

func (r *repository) regularWorkingFile(path string) error {
	parts := strings.Split(filepath.ToSlash(path), "/")
	current := r.root
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return &inputError{fmt.Errorf("unsafe working-tree source path %q", path)}
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return err
			}
			return &inputError{fmt.Errorf("cannot inspect working-tree source %s: %w", path, err)}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &inputError{fmt.Errorf("unsafe working-tree source %s: symlink component %s", path, strings.Join(parts[:i+1], "/"))}
		}
		if i == len(parts)-1 {
			if !info.Mode().IsRegular() {
				return &inputError{fmt.Errorf("unsafe working-tree source %s: not a regular file", path)}
			}
		} else if !info.IsDir() {
			return &inputError{fmt.Errorf("unsafe working-tree source %s: non-directory component %s", path, strings.Join(parts[:i+1], "/"))}
		}
	}
	return nil
}

// ProposalPaths returns root-relative .new-tag paths using the tag creator's
// exact discovery pattern. Every discovered path must be a regular file with
// no symlink components. Discovery inspects names, not proposal contents.
func ProposalPaths(root string) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	r := &repository{root: root}
	// Glob traverses directory symlinks when discovering names; validate
	// components before callers read any contents.
	matches, err := filepath.Glob(filepath.Join(root, "*", ".new-tag"))
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, match := range matches {
		p, err := filepath.Rel(root, match)
		if err != nil {
			return nil, err
		}
		p = filepath.ToSlash(p)
		if err := r.regularWorkingFile(p); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func (r *repository) paths(ref string) ([]string, error) {
	if ref != "" {
		out, err := r.git("ls-tree", "-r", "--name-only", "-z", ref)
		return strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00"), err
	}
	// Include untracked candidate specs and proposals, without scanning .git or
	// dependencies. Only root Markdown and one-level .new-tag files are served.
	entries, err := os.ReadDir(r.root)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".md") {
			paths = append(paths, e.Name())
		}
	}
	// Use exactly the same discovery and safety checks as the tag creator.
	proposals, err := ProposalPaths(r.root)
	if err != nil {
		return nil, err
	}
	return append(paths, proposals...), nil
}

func (r *repository) commit(ref, tip string) (string, error) {
	out, err := r.git("rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("missing commit %q", ref)
	}
	hash := strings.TrimSpace(string(out))
	if _, err := r.git("merge-base", "--is-ancestor", hash, tip); err != nil {
		return "", fmt.Errorf("commit %q is not reachable from main", ref)
	}
	return hash, nil
}

var hunkRE = regexp.MustCompile(`(?m)^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// unchangedLines uses Git's actual source diff, not URL identity or a multiset
// of links. A newly copied occurrence must not inherit another occurrence's debt.
func unchangedLines(old, new []byte) (map[int]int, error) {
	dir, err := os.MkdirTemp("", "c2sp-linkcheck-diff-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	a, b := filepath.Join(dir, "base"), filepath.Join(dir, "candidate")
	if err := os.WriteFile(a, old, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(b, new, 0600); err != nil {
		return nil, err
	}
	cmd := exec.Command("git", "diff", "--no-index", "--no-ext-diff", "--no-textconv", "--unified=0", "--", a, b)
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			return nil, fmt.Errorf("source diff: %w", err)
		}
	}
	result := make(map[int]int)
	oldLine, newLine := 1, 1
	for _, h := range hunkRE.FindAllStringSubmatch(string(out), -1) {
		oldStart, _ := strconv.Atoi(h[1])
		newStart, _ := strconv.Atoi(h[3])
		oldCount, newCount := 1, 1
		if h[2] != "" {
			oldCount, _ = strconv.Atoi(h[2])
		}
		if h[4] != "" {
			newCount, _ = strconv.Atoi(h[4])
		}
		if oldCount == 0 {
			oldStart++
		}
		if newCount == 0 {
			newStart++
		}
		for oldLine < oldStart && newLine < newStart {
			result[newLine] = oldLine
			oldLine++
			newLine++
		}
		oldLine, newLine = oldStart+oldCount, newStart+newCount
	}
	for newLine <= bytes.Count(new, []byte("\n"))+1 {
		result[newLine] = oldLine
		oldLine++
		newLine++
	}
	return result, nil
}
