package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"c2sp.org/C2SP/website/spec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := &http.Server{Addr: ":9091", Handler: metricsMux,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() { log.Fatal(metricsServer.ListenAndServe()) }()

	ctx := context.Background()

	repo, err := InitRepo(ctx, os.TempDir())
	if err != nil {
		log.Fatal(err)
	}

	h := handler(repo)
	s := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}),
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
		IdleTimeout:  10 * time.Minute,
	}

	log.Fatal(s.ListenAndServe())
}

func handler(repo *Repo) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.Handle("POST /_fetch", repo.FetchHandler())

	mux.Handle("/{$}", http.RedirectHandler("https://github.com/C2SP/C2SP/", http.StatusFound))
	mux.Handle("/CCTV", http.RedirectHandler("https://github.com/C2SP/CCTV/", http.StatusFound))

	mux.HandleFunc("/{name}", func(w http.ResponseWriter, r *http.Request) {
		name, vers, ok := strings.Cut(r.PathValue("name"), "@")
		if !ok {
			vers = "latest"
		}
		if !spec.ValidName(name) {
			http.Error(w, "invalid spec name", http.StatusBadRequest)
			return
		}

		if vers == "latest" {
			var err error
			vers, err = repo.Latest(name)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to get latest version: %v", err), http.StatusInternalServerError)
				return
			}
			if vers == "" {
				vers = "main"
			}
		}

		versions, err := repo.Versions(name)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get versions: %v", err), http.StatusInternalServerError)
			return
		}

		if vers == "main" {
			http.Redirect(w, r, "https://github.com/C2SP/C2SP/blob/main/"+name+".md", http.StatusFound)
		} else if slices.Contains(versions, vers) {
			http.Redirect(w, r, "https://github.com/C2SP/C2SP/blob/"+name+"/"+vers+"/"+name+".md", http.StatusFound)
		} else if repo.IsCommit(vers) {
			http.Redirect(w, r, "https://github.com/C2SP/C2SP/blob/"+vers+"/"+name+".md", http.StatusFound)
		} else {
			http.Error(w, "version not found", http.StatusNotFound)
		}
	})

	mux.HandleFunc("/CCTV/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !spec.ValidName(name) {
			http.Error(w, "invalid spec name", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://github.com/C2SP/CCTV/tree/main/"+name, http.StatusFound)
	})

	// Renamed test vectors and specs.
	mux.Handle("/CCTV/ed25519vectors", http.RedirectHandler("https://c2sp.org/CCTV/ed25519", http.StatusFound))
	mux.Handle("/sunlight", http.RedirectHandler("https://c2sp.org/static-ct-api", http.StatusFound))

	goGetMux := http.NewServeMux()
	goGetMux.Handle("/", GoImportHandler("c2sp.org", "https://github.com/C2SP/C2SP"))
	goGetMux.Handle("/CCTV/", GoImportHandler("c2sp.org/CCTV", "https://github.com/C2SP/CCTV"))

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w := &trackingResponseWriter{ResponseWriter: rw}
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// Divert Go module downloads to the go-get handler.
		if r.URL.Query().Get("go-get") == "1" {
			goGetMux.ServeHTTP(w, r)
			return
		}

		_, pattern := mux.Handler(r)
		httpReqs.WithLabelValues(pattern).Inc()

		// Send browser navigation requests to Plausible Analytics.
		if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
			defer func() {
				go plausiblePageview(r, w.statusCode, pattern)
			}()
		}

		mux.ServeHTTP(w, r)
	})
}

func GoImportHandler(module, repo string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		goGetReqs.WithLabelValues(module).Inc()
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprintf(w, `<head><meta name="go-import" content="%s git %s">`, module, repo)
	})
}

type trackingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// Unwrap returns the original ResponseWriter for [http.ResponseController].
func (w *trackingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *trackingResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *trackingResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

var plausibleClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
}

func plausiblePageview(r *http.Request, statusCode int, pattern string) {
	// https://plausible.io/docs/events-api
	type Event struct {
		Domain   string         `json:"domain"`
		Name     string         `json:"name"`
		URL      string         `json:"url"`
		Referrer string         `json:"referrer"`
		Props    map[string]any `json:"props,omitempty"`
	}
	event := Event{
		Domain:   "c2sp.org", // https://plausible.io/docs/subdomain-hostname-filter
		Name:     "pageview",
		URL:      r.Header.Get("X-Forwarded-Proto") + "://" + r.Host + r.URL.String(),
		Referrer: r.Referer(),
		Props: map[string]any{
			"HTTP Status Code": statusCode,
			"HTTP Method":      r.Method,
			"Mux Pattern":      pattern,
		},
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal Plausible event: %v", err)
		plausibleEvents.WithLabelValues("false").Inc()
		return
	}
	req, err := http.NewRequest("POST", "https://plausible.io/api/event", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to create Plausible event request: %v", err)
		plausibleEvents.WithLabelValues("false").Inc()
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", r.UserAgent())
	req.Header.Set("X-Forwarded-For", r.Header.Get("Fly-Client-IP"))
	if testing.Testing() {
		return
	}
	resp, err := plausibleClient.Do(req)
	if err != nil {
		log.Printf("Failed to send Plausible event: %v", err)
		plausibleEvents.WithLabelValues("false").Inc()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Plausible event failed with status %d: %s", resp.StatusCode, body)
		plausibleEvents.WithLabelValues("false").Inc()
		return
	}
	plausibleEvents.WithLabelValues("true").Inc()
}

var goGetReqs = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goget_requests_total",
	Help: "go get requests processed, partitioned by repository name.",
}, []string{"name"})
var httpReqs = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "http_requests_total",
	Help: "HTTP requests processed, partitioned by handler, excluding goget_requests_total.",
}, []string{"handler"})
var plausibleEvents = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "plausible_events_total",
	Help: "Plausible Analytics events sent.",
}, []string{"success"})
