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
	"strings"
	"sync"
	"time"
)

const repoURL = "https://github.com/C2SP/C2SP.git"

var repo *Repo

// Repo is a local bare mirror of the upstream repository, kept up to date by
// periodic fetches.
type Repo struct {
	dir    string
	mu     sync.RWMutex
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
	}
	r.dir = dir
	if _, err := r.git("remote", "add", "origin", repoURL); err != nil {
		return nil, err
	}
	if err := r.fetch(); err != nil {
		return nil, err
	}
	go r.fetchLoop(ctx)
	return r, nil
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
	if _, err := r.git("fetch", "--depth=1", "origin", "main"); err != nil {
		return err
	}

	// Fetch tags.
	_, err := r.git("fetch", "--depth=1", "origin", "+refs/tags/*:refs/tags/*")
	return err
}

// Fetch signals the fetch loop to run immediately. It does not block.
func (r *Repo) Fetch() {
	select {
	case r.fetchC <- struct{}{}:
	default:
	}
}

// FetchHandler returns an HTTP handler for POST /_fetch that triggers a fetch
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
			log.Printf("/_fetch: received fan-out request, fetching locally")
			r.Fetch()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Fan out to all instances via Fly internal DNS, including this one.
		addrs, err := net.LookupHost("c2sp.internal")
		if err != nil {
			log.Printf("/_fetch: DNS lookup failed: %v, fetching locally", err)
			r.Fetch()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for _, addr := range addrs {
			go func() {
				fanReq, err := http.NewRequest("POST", "http://["+addr+"]:8080/_fetch?fanout=1", nil)
				if err != nil {
					log.Printf("/_fetch: fan-out request: %v", err)
					return
				}
				fanReq.Header.Set("Authorization", "Bearer "+token)
				resp, err := http.DefaultClient.Do(fanReq)
				if err != nil {
					log.Printf("/_fetch: fan-out to %s: %v", addr, err)
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
