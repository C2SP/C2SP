package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"c2sp.org/C2SP/website/spec"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: create-tag <repo-root>")
	}
	if err := os.Chdir(os.Args[1]); err != nil {
		log.Fatalf("failed to chdir to %s: %v", os.Args[1], err)
	}

	matches, err := filepath.Glob("*/.new-tag")
	if err != nil {
		log.Fatalf("failed to glob for .new-tag files: %v", err)
	}
	if len(matches) == 0 {
		log.Printf("no .new-tag files found, nothing to do")
		return
	}

	var failed bool
	for _, match := range matches {
		specName := filepath.Dir(match)
		if err := processNewTag(match); err != nil {
			log.Printf("[%s] error: %v", specName, err)
			failed = true
		}
	}

	if failed {
		log.Fatalf("some .new-tag files failed to process")
	}
}

func processNewTag(match string) error {
	specName := filepath.Dir(match)
	log.Printf("[%s] processing %s", specName, match)

	data, err := os.ReadFile(match)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	lines := slices.Collect(strings.Lines(string(data)))
	if len(lines) != 2 {
		return fmt.Errorf("expected 2 lines (version and commit hash), got %d", len(lines))
	}

	version := strings.TrimSpace(lines[0])
	commitHash := strings.TrimSpace(lines[1])

	if !spec.ValidVersion(version) {
		return fmt.Errorf("invalid semver version %q", version)
	}

	if len(commitHash) != 40 {
		return fmt.Errorf("invalid commit hash %q: expected 40 hex characters, got %d", commitHash, len(commitHash))
	}
	if _, err := hex.DecodeString(commitHash); err != nil {
		return fmt.Errorf("invalid commit hash %q: not valid hex: %v", commitHash, err)
	}

	if err := gitCmd("merge-base", "--is-ancestor", "--end-of-options", commitHash, "origin/main"); err != nil {
		return fmt.Errorf("commit %s is not reachable from main: %v", commitHash, err)
	}

	tagName := specName + "/" + version
	log.Printf("[%s] creating tag %s at %s", specName, tagName, commitHash)

	if err := gitCmd("tag", "--end-of-options", tagName, commitHash); err != nil {
		return fmt.Errorf("failed to create tag %s: %v", tagName, err)
	}

	if err := os.Remove(match); err != nil {
		return fmt.Errorf("failed to remove %s: %v", match, err)
	}

	log.Printf("[%s] successfully created tag %s", specName, tagName)
	return nil
}

func gitCmd(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
