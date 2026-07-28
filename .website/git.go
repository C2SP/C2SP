package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/semver"
)

const repoURL = "https://github.com/C2SP/C2SP.git"

var commitHashRE = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// Repo is a local bare mirror of the upstream repository, kept up to date by
// periodic fetches.
type Repo struct {
	dir    string
	mu     sync.RWMutex
	gen    atomic.Uint64
	fetchC chan struct{} // signal to trigger an immediate fetch
}

// InitRepo initializes a bare repository in os.TempDir, fetches origin/main
// and tags, and starts a background goroutine that re-fetches every five
// minutes.
func InitRepo(ctx context.Context, tmpDir string) (*Repo, error) {
	dir := filepath.Join(tmpDir, "C2SP.git")
	r := &Repo{fetchC: make(chan struct{}, 1)}
	if _, err := os.Stat(dir); err != nil {
		if _, err := r.git("init", "--bare", dir); err != nil {
			return nil, err
		}
		r.dir = dir
		if _, err := r.git("remote", "add", "origin", repoURL); err != nil {
			return nil, err
		}
	} else {
		// The repository survived from a previous run; make sure the remote
		// points at the right URL.
		r.dir = dir
		if _, err := r.git("remote", "set-url", "origin", repoURL); err != nil {
			return nil, err
		}
	}
	if err := r.fetch(); err != nil {
		return nil, err
	}
	go r.fetchLoop(ctx)
	return r, nil
}

// ImportRepo initializes a bare repository from a fast-export stream. The repo
// will not support fetching, but can be used for testing.
//
// It also returns a map from mark (like ":1") to commit hash, which can be used
// in tests to refer to specific commits in the stream.
func ImportRepo(ctx context.Context, exportFile, tmpDir string) (*Repo, map[string]string, error) {
	dir := filepath.Join(tmpDir, "C2SP.git")
	r := &Repo{}
	if _, err := os.Stat(dir); err != nil {
		if _, err := r.git("init", "--bare", dir); err != nil {
			return nil, nil, err
		}
	}
	r.dir = dir

	f, err := os.Open(exportFile)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	cmd := exec.Command("git", "fast-import", "--quiet", "--export-marks="+filepath.Join(tmpDir, "marks.txt"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = f
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("git fast-import: %w\n%s", err, stderr.Bytes())
	}

	marksData, err := os.ReadFile(filepath.Join(tmpDir, "marks.txt"))
	if err != nil {
		return nil, nil, fmt.Errorf("read marks: %w", err)
	}
	marks := make(map[string]string)
	for line := range strings.Lines(string(marksData)) {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid marks line: %q", line)
		}
		marks[parts[0]] = parts[1]
	}

	return r, marks, nil
}

func (r *Repo) fetchLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.fetchC:
		}
		if err := r.fetch(); err != nil {
			log.Printf("git fetch: %v", err)
		}
	}
}

func (r *Repo) fetch() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Fetch latest main.
	if _, err := r.git("fetch", "origin", "main"); err != nil {
		return err
	}

	// Fetch tags. Note that this must not use --depth, which would mark the
	// repository as shallow and break the reachability check in IsCommit.
	// Tagged commits are reachable from main, so this fetches no extra history.
	if _, err := r.git("fetch", "origin", "+refs/tags/*:refs/tags/*"); err != nil {
		return err
	}

	r.gen.Add(1)
	return nil
}

// Generation returns a counter that increments on every successful fetch. It
// can be used to invalidate caches of repository-derived data.
func (r *Repo) Generation() uint64 {
	return r.gen.Load()
}

// Fetch signals the fetch loop to run immediately. It does not block.
func (r *Repo) Fetch() {
	if r.fetchC == nil {
		return
	}
	select {
	case r.fetchC <- struct{}{}:
	default:
	}
}

// FetchHandler returns an HTTP handler for POST /-/fetch that triggers a fetch
// on all Fly.io instances. It requires a Bearer token matching the FETCH_TOKEN
// environment variable.
func (r *Repo) FetchHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := os.Getenv("FETCH_TOKEN")
		if token == "" {
			http.Error(w, "FETCH_TOKEN not configured", http.StatusInternalServerError)
			return
		}
		if req.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// If this is an internal fan-out request, just fetch locally.
		if req.URL.Query().Get("fanout") == "1" {
			log.Printf("/-/fetch: received fan-out request, fetching locally")
			r.Fetch()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Fan out to all instances via Fly internal DNS, including this one.
		addrs, err := net.LookupHost("c2sp.internal")
		if err != nil {
			log.Printf("/-/fetch: DNS lookup failed: %v, fetching locally", err)
			r.Fetch()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for _, addr := range addrs {
			go func() {
				fanReq, err := http.NewRequest("POST", "http://["+addr+"]:8080/-/fetch?fanout=1", nil)
				if err != nil {
					log.Printf("/-/fetch: fan-out request: %v", err)
					return
				}
				fanReq.Header.Set("Authorization", "Bearer "+token)
				resp, err := http.DefaultClient.Do(fanReq)
				if err != nil {
					log.Printf("/-/fetch: fan-out to %s: %v", addr, err)
					return
				}
				resp.Body.Close()
			}()
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// FileAt returns the contents of a file at the given tag, or at origin/main
// if tag is empty.
func (r *Repo) FileAt(path, tag string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ref := "origin/main"
	if tag != "" {
		if strings.Contains(tag, ":") {
			return nil, fmt.Errorf("invalid tag %q", tag)
		}
		ref = tag
	}
	return r.git("show", "--end-of-options", ref+":"+path)
}

// CommitTime returns the committer time of the given ref.
func (r *Repo) CommitTime(ref string) (time.Time, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if strings.Contains(ref, ":") {
		return time.Time{}, fmt.Errorf("invalid ref %q", ref)
	}
	out, err := r.git("log", "-1", "--format=%cI", "--end-of-options", ref, "--")
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(string(out)))
}

// Specs returns the names of the top-level .md files at origin/main, sorted
// case-insensitively.
func (r *Repo) Specs() ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out, err := r.git("ls-tree", "--name-only", "origin/main")
	if err != nil {
		return nil, err
	}
	var specs []string
	for line := range strings.Lines(string(out)) {
		line = strings.TrimSuffix(line, "\n")
		name, ok := strings.CutSuffix(line, ".md")
		if !ok {
			continue
		}
		specs = append(specs, name)
	}
	slices.SortFunc(specs, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return specs, nil
}

// Versions returns the sorted list of semver versions for the given spec name,
// based on git tags of the form "name/vX.Y.Z".
func (r *Repo) Versions(name string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out, err := r.git("tag", "-l", "--end-of-options", name+"/*")
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	var versions []string
	for line := range strings.Lines(string(out)) {
		line = strings.TrimSuffix(line, "\n")
		v := strings.TrimPrefix(line, name+"/")
		if semver.IsValid(v) {
			versions = append(versions, v)
		}
	}
	semver.Sort(versions)
	return versions, nil
}

// latestVersion returns the latest of a sorted list of versions, following
// Go's @latest logic: the highest non-prerelease version, or the highest
// prerelease version if no releases exist. It returns "" if there are no
// versions.
func latestVersion(versions []string) string {
	var latestRelease, latestPrerelease string
	for _, v := range versions {
		if semver.Prerelease(v) != "" {
			latestPrerelease = v
		} else {
			latestRelease = v
		}
	}
	if latestRelease != "" {
		return latestRelease
	}
	return latestPrerelease
}

// IsCommit returns whether the given ref is a valid git commit hash reachable
// from origin/main, potentially truncated.
func (r *Repo) IsCommit(ref string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !commitHashRE.MatchString(ref) {
		return false
	}

	out, err := r.git("rev-parse", "--quiet", "--verify", ref+"^{commit}")
	if err != nil {
		return false
	}
	commit := strings.TrimSpace(string(out))

	_, err = r.git("merge-base", "--is-ancestor", commit, "origin/main")
	return err == nil
}

// git runs a git command against the repository and returns its stdout.
func (r *Repo) git(args ...string) ([]byte, error) {
	if r.dir != "" {
		args = append([]string{"-C", r.dir}, args...)
	}
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %q: %w\n%s", args, err, stderr.Bytes())
	}
	return stdout.Bytes(), nil
}
