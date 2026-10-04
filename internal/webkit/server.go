package webkit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

//go:embed assets/*
var assets embed.FS

type jobEntry struct {
	job    Job
	cancel context.CancelFunc
}

type Server struct {
	ctx     context.Context
	stop    context.CancelFunc
	runner  Runner
	version string
	host    string
	token   string
	mu      sync.Mutex
	jobs    map[string]*jobEntry
	order   []string
	active  string
	closed  bool
	workers sync.WaitGroup
}

func NewServer(ctx context.Context, runner Runner, version, address string) (*Server, error) {
	host, port, err := net.SplitHostPort(address)
	number, numberErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || numberErr != nil || number < 1 || number > 65535 {
		return nil, errors.New("the web interface requires a bound 127.0.0.1 address")
	}
	if runner == nil {
		return nil, errors.New("a CLI runner is required")
	}
	token, err := randomID(32)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(ctx)
	return &Server{ctx: ctx, stop: stop, runner: runner, version: version, host: address,
		token: token, jobs: map[string]*jobEntry{}, order: []string{}}, nil
}

func randomID(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("could not initialize local session")
	}
	return hex.EncodeToString(value), nil
}

func (server *Server) Close() {
	server.mu.Lock()
	server.closed = true
	server.stop()
	server.mu.Unlock()
	server.workers.Wait()
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func problem(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}

func (server *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(remote) == nil || !net.ParseIP(remote).IsLoopback() || r.Host != server.host {
		problem(w, http.StatusForbidden, "Use the local URL printed by inspectyn-web.")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+server.host {
		problem(w, http.StatusForbidden, "Cross-origin requests are not allowed.")
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "none" && site != "same-origin" {
		problem(w, http.StatusForbidden, "Open Inspectyn directly from its local URL.")
		return
	}
	if r.Method == http.MethodPost {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Inspectyn-Token")), []byte(server.token)) != 1 {
			problem(w, http.StatusForbidden, "The local session changed. Reload the page and try again.")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			problem(w, http.StatusUnsupportedMediaType, "Send application/json.")
			return
		}
	}
	path := r.URL.Path
	switch {
	case path == "/favicon.ico":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case path == "/" || path == "/app.js" || path == "/style.css":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		file, contentType := "index.html", "text/html; charset=utf-8"
		if path == "/app.js" {
			file, contentType = "app.js", "text/javascript; charset=utf-8"
		} else if path == "/style.css" {
			file, contentType = "style.css", "text/css; charset=utf-8"
		}
		data, err := assets.ReadFile("assets/" + file)
		if err != nil {
			problem(w, http.StatusInternalServerError, "Interface asset is unavailable.")
			return
		}
		w.Header().Set("Content-Type", contentType)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case path == "/api/session":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		reply(w, http.StatusOK, map[string]any{"token": server.token, "version": server.version,
			"maxTargets": inspect.MaxTargets, "historyLimit": HistoryLimit})
	case path == "/api/jobs":
		switch r.Method {
		case http.MethodGet:
			server.mu.Lock()
			jobs := make([]Job, 0, len(server.order))
			for _, id := range server.order {
				job := server.jobs[id].job
				job.Report = nil
				jobs = append(jobs, job)
			}
			server.mu.Unlock()
			reply(w, http.StatusOK, map[string]any{"jobs": jobs})
		case http.MethodPost:
			server.start(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case strings.HasPrefix(path, "/api/jobs/"):
		server.jobRoute(w, r)
	default:
		problem(w, http.StatusNotFound, "Not found.")
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	problem(w, http.StatusMethodNotAllowed, "Method not allowed.")
}

func decodeBody(w http.ResponseWriter, r *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return errors.New("Request must contain valid JSON, at most 64 KiB.")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("Send one JSON object.")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("Send a JSON object.")
	}
	for _, field := range fields {
		if bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return errors.New("Request fields cannot be null.")
		}
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if strict.Decode(value) != nil {
		return errors.New("Request contains an unknown field or an invalid value.")
	}
	return nil
}

func (server *Server) start(w http.ResponseWriter, r *http.Request) {
	request := Request{DNS: true, TimeoutMS: 10000, Concurrency: 4, FailOn: "high"}
	if err := decodeBody(w, r, &request); err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	request, err := ValidateRequest(request)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := randomID(12)
	if err != nil {
		problem(w, http.StatusInternalServerError, err.Error())
		return
	}
	server.mu.Lock()
	if server.closed || server.ctx.Err() != nil {
		server.mu.Unlock()
		problem(w, http.StatusServiceUnavailable, "Inspectyn is shutting down.")
		return
	}
	if server.active != "" {
		server.mu.Unlock()
		problem(w, http.StatusConflict, "A run is already active. Wait for it to finish or cancel it.")
		return
	}
	if len(server.order) == HistoryLimit {
		delete(server.jobs, server.order[len(server.order)-1])
		server.order = server.order[:len(server.order)-1]
	}
	ctx, cancel := context.WithTimeout(server.ctx, runDeadline(request))
	job := Job{ID: id, Kind: request.Kind, Targets: request.Targets, State: "running", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	server.jobs[id] = &jobEntry{job: job, cancel: cancel}
	server.order = append([]string{id}, server.order...)
	server.active = id
	server.workers.Add(1)
	server.mu.Unlock()
	go server.execute(ctx, cancel, id, request)
	reply(w, http.StatusAccepted, job)
}

func (server *Server) execute(ctx context.Context, cancel context.CancelFunc, id string, request Request) {
	defer server.workers.Done()
	defer cancel()
	result, err := server.runner.Run(ctx, request)
	server.mu.Lock()
	defer server.mu.Unlock()
	entry := server.jobs[id]
	entry.job.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	entry.cancel = nil
	server.active = ""
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		entry.job.State = "canceled"
		entry.job.Error = "Run canceled. No complete report was saved."
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		entry.job.State = "failed"
		entry.job.Error = "Run exceeded its time limit. Try fewer targets or shorter phase timeouts."
	case err != nil:
		entry.job.State, entry.job.Error = "failed", err.Error()
	case result.Report == nil:
		entry.job.State, entry.job.Error = "failed", "The CLI did not return a report."
	default:
		entry.job.State, entry.job.Report = "completed", result.Report
		entry.job.ExitCode = &result.ExitCode
	}
}

func (server *Server) jobRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/jobs/"), "/")
	if len(parts) > 2 || len(parts[0]) != 24 {
		problem(w, http.StatusNotFound, "Run not found.")
		return
	}
	id := parts[0]
	server.mu.Lock()
	entry, exists := server.jobs[id]
	if !exists {
		server.mu.Unlock()
		problem(w, http.StatusNotFound, "Run not found. History is cleared when the server stops.")
		return
	}
	job := entry.job
	server.mu.Unlock()
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		reply(w, http.StatusOK, job)
		return
	}
	switch parts[1] {
	case "cancel":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		var empty struct{}
		if err := decodeBody(w, r, &empty); err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		server.mu.Lock()
		// A completed run can be evicted while this request is decoded.
		if entry, exists := server.jobs[id]; exists {
			if entry.cancel != nil {
				entry.cancel()
			}
			job = entry.job
		}
		server.mu.Unlock()
		reply(w, http.StatusOK, job)
	case "report":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		if job.Report == nil {
			problem(w, http.StatusConflict, "This run has no report to download.")
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}
		types := map[string]string{"json": "application/json", "text": "text/plain", "markdown": "text/markdown", "html": "text/html"}
		extensions := map[string]string{"json": "json", "text": "txt", "markdown": "md", "html": "html"}
		contentType, allowed := types[format]
		if !allowed {
			problem(w, http.StatusBadRequest, "Choose json, html, markdown or text.")
			return
		}
		data, err := inspect.RenderReport(*job.Report, format)
		if err != nil {
			problem(w, http.StatusInternalServerError, "Could not render this report.")
			return
		}
		w.Header().Set("Content-Type", contentType+"; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="inspectyn-%s.%s"`, id, extensions[format]))
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
		_, _ = w.Write(data)
	default:
		problem(w, http.StatusNotFound, "Not found.")
	}
}
