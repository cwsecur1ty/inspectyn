package webkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

type runnerFunc func(context.Context, Request) (Result, error)

func (f runnerFunc) Run(ctx context.Context, request Request) (Result, error) { return f(ctx, request) }

func fixtureResult(request Request) Result {
	return Result{ExitCode: 0, Report: &inspect.Report{SchemaVersion: 1,
		Tool: inspect.Tool{Name: "inspectyn", Version: inspect.Version}, Kind: request.Kind,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Complete: true,
		Targets: request.Targets, Findings: []inspect.Finding{}, Errors: []inspect.CheckError{},
		Observations: []inspect.Observation{}, Context: map[string]any{}}}
}

func testServer(t *testing.T, runner Runner) *Server {
	t.Helper()
	server, err := NewServer(context.Background(), runner, inspect.Version, "127.0.0.1:8788")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return server
}

func localRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1:8788"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:43210"
	return r
}

func perform(server *Server, method, path, body string) *httptest.ResponseRecorder {
	r := localRequest(method, path, body)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Inspectyn-Token", server.token)
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}

func decodeJob(t *testing.T, response *httptest.ResponseRecorder) Job {
	t.Helper()
	var job Job
	if err := json.Unmarshal(response.Body.Bytes(), &job); err != nil || job.ID == "" {
		t.Fatalf("invalid job: %s (%v)", response.Body, err)
	}
	return job
}

func awaitJob(t *testing.T, server *Server, id string) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job := decodeJob(t, perform(server, "GET", "/api/jobs/"+id, ""))
		if job.State != "running" {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job did not settle")
	return Job{}
}

func TestLocalBrowserBoundary(t *testing.T) {
	var calls atomic.Int32
	server := testServer(t, runnerFunc(func(_ context.Context, request Request) (Result, error) {
		calls.Add(1)
		return fixtureResult(request), nil
	}))
	for _, change := range []struct {
		name string
		edit func(*http.Request)
	}{
		{"rebound host", func(r *http.Request) { r.Host = "attacker.example:8788" }},
		{"wrong port", func(r *http.Request) { r.Host = "127.0.0.1:8789" }},
		{"remote client", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:54321" }},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"same site other origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := localRequest("GET", "/api/session", "")
			change.edit(r)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), server.token) {
				t.Fatalf("boundary response = %d %s", w.Code, w.Body)
			}
		})
	}
	for _, token := range []string{"", "wrong"} {
		r := localRequest("POST", "/api/jobs", `{"kind":"recon","targets":["example.com"]}`)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Inspectyn-Token", token)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("missing token accepted: %d", w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected requests reached the CLI")
	}
	response := perform(server, "GET", "/api/session", "")
	var session map[string]any
	if json.Unmarshal(response.Body.Bytes(), &session) != nil || session["token"] != server.token || session["version"] != inspect.Version {
		t.Fatalf("session = %s", response.Body)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("session must stay same-origin and uncached")
	}
}

func TestRequestValidationBeforeExecution(t *testing.T) {
	var calls atomic.Int32
	server := testServer(t, runnerFunc(func(_ context.Context, request Request) (Result, error) {
		calls.Add(1)
		return fixtureResult(request), nil
	}))
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"kind":"review","targets":["example.com"]}`,
		`{"kind":"scan","targets":["https://example.com"],"args":["--out","secret"]}`,
		`{"kind":"scan","targets":["https://example.com"],"dns":null}`,
		`{"kind":"scan","targets":["https://example.com"],"dnsDetails":null}`,
		`{"kind":"scan","targets":["https://example.com"],"securityTxt":null}`,
		`{"kind":"scan","targets":["https://user:secret@example.com"]}`,
		`{"kind":"scan","targets":["https://127.0.0.1"]}`,
		`{"kind":"scan","targets":["https://example.com"],"concurrency":0}`,
		`{"kind":"recon","targets":["example.com/path"]}`,
		`{"kind":"recon","targets":["example.com"],"securityTxt":true}`,
		`{"kind":"recon","targets":["example.com","example.com"]}`,
		`{"kind":"recon","targets":["example.com"],"failOn":"invalid"}`,
		`{"kind":"recon","targets":["example.com"]} {}`,
		`{"kind":"recon","targets":["` + strings.Repeat("x", 65536) + `"]}`,
	} {
		response := perform(server, "POST", "/api/jobs", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid request returned %d", response.Code)
		}
		if strings.Contains(response.Body.String(), "secret") {
			t.Fatal("raw target data leaked into validation error")
		}
	}
	r := localRequest("POST", "/api/jobs", `{}`)
	r.Header.Set("X-Inspectyn-Token", server.token)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType || calls.Load() != 0 {
		t.Fatal("invalid request reached runner")
	}
}

func TestRunCancelAndGlobalConcurrency(t *testing.T) {
	started := make(chan Request, 1)
	server := testServer(t, runnerFunc(func(ctx context.Context, request Request) (Result, error) {
		started <- request
		<-ctx.Done()
		return Result{}, ctx.Err()
	}))
	response := perform(server, "POST", "/api/jobs", `{"kind":"recon","targets":["EXAMPLE.COM"]}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("start = %d %s", response.Code, response.Body)
	}
	job := decodeJob(t, response)
	request := <-started
	if request.Targets[0] != "https://example.com/" || request.TimeoutMS != 10000 || !request.DNS {
		t.Fatalf("defaults and normalization = %+v", request)
	}
	if perform(server, "POST", "/api/jobs", `{"kind":"recon","targets":["other.example"]}`).Code != http.StatusConflict {
		t.Fatal("parallel run was allowed")
	}
	if perform(server, "GET", "/api/jobs/"+job.ID+"/cancel", "").Code != http.StatusMethodNotAllowed {
		t.Fatal("GET canceled a job")
	}
	if perform(server, "POST", "/api/jobs/"+job.ID+"/cancel", `{}`).Code != http.StatusOK {
		t.Fatal("cancel failed")
	}
	job = awaitJob(t, server, job.ID)
	if job.State != "canceled" || job.Report != nil || job.FinishedAt == "" {
		t.Fatalf("canceled job = %+v", job)
	}
	if perform(server, "GET", "/api/jobs/"+job.ID+"/report", "").Code != http.StatusConflict {
		t.Fatal("canceled run has a download")
	}
}

func TestReportsAndBoundedHistory(t *testing.T) {
	server := testServer(t, runnerFunc(func(_ context.Context, request Request) (Result, error) {
		result := fixtureResult(request)
		result.Report.Complete = false
		result.Report.Errors = []inspect.CheckError{{Target: request.Targets[0], Code: "TEST", Message: "<script>alert(1)</script>"}}
		result.ExitCode = 2
		return result, nil
	}))
	var first, last Job
	for i := range HistoryLimit + 1 {
		response := perform(server, "POST", "/api/jobs", fmt.Sprintf(`{"kind":"recon","targets":["host%d.example"]}`, i))
		if response.Code != http.StatusAccepted {
			t.Fatalf("start = %d %s", response.Code, response.Body)
		}
		last = awaitJob(t, server, decodeJob(t, response).ID)
		if i == 0 {
			first = last
		}
	}
	if last.State != "completed" || last.Report == nil || last.ExitCode == nil || *last.ExitCode != 2 {
		t.Fatalf("incomplete report was discarded: %+v", last)
	}
	if perform(server, "GET", "/api/jobs/"+first.ID, "").Code != http.StatusNotFound {
		t.Fatal("oldest run was not evicted")
	}
	var history struct {
		Jobs []Job `json:"jobs"`
	}
	list := perform(server, "GET", "/api/jobs", "")
	if json.Unmarshal(list.Body.Bytes(), &history) != nil || len(history.Jobs) != HistoryLimit || history.Jobs[0].ID != last.ID {
		t.Fatalf("history = %s", list.Body)
	}
	if history.Jobs[0].Report != nil {
		t.Fatal("history list should omit full report payloads")
	}
	for _, format := range []string{"json", "html", "markdown", "text"} {
		response := perform(server, "GET", "/api/jobs/"+last.ID+"/report?format="+format, "")
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Disposition"), "attachment;") {
			t.Fatalf("download %s = %d %s", format, response.Code, response.Body)
		}
		if format == "html" && strings.Contains(response.Body.String(), "<script>") {
			t.Fatal("unsafe HTML report")
		}
	}
}

func TestExpandedOptionsAndObservationDownloads(t *testing.T) {
	requests := make(chan Request, 1)
	server := testServer(t, runnerFunc(func(_ context.Context, request Request) (Result, error) {
		requests <- request
		result := fixtureResult(request)
		result.Report.Observations = []inspect.Observation{enrichedObservation(request.Targets[0], result.Report.GeneratedAt)}
		return result, nil
	}))
	response := perform(server, "POST", "/api/jobs", `{"kind":"scan","targets":["https://company.example/path"],"dnsDetails":true,"securityTxt":true}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expanded request = %d %s", response.Code, response.Body)
	}
	job := awaitJob(t, server, decodeJob(t, response).ID)
	request := <-requests
	if !request.DNSDetails || !request.SecurityTXT || !request.DNS || job.State != "completed" || job.Report == nil {
		t.Fatalf("options or report lost: %+v %+v", request, job)
	}
	for _, format := range []string{"json", "html", "markdown", "text"} {
		response := perform(server, "GET", "/api/jobs/"+job.ID+"/report?format="+format, "")
		if response.Code != http.StatusOK {
			t.Fatalf("download %s = %d %s", format, response.Code, response.Body)
		}
		for _, retained := range []string{"Fixture issuer", "TLS_AES_128_GCM_SHA256", "edge.company.example", "sameSite", "/.well-known/security.txt"} {
			if !strings.Contains(response.Body.String(), retained) {
				t.Fatalf("%s download omitted %s", format, retained)
			}
		}
		if format == "json" {
			var downloaded struct {
				inspect.Report
				Coverage struct {
					Status    string `json:"status"`
					Statement string `json:"statement"`
				} `json:"coverage"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &downloaded); err != nil || !reflect.DeepEqual(downloaded.Observations, job.Report.Observations) || downloaded.Coverage.Status != "complete" || downloaded.Coverage.Statement == "" {
				t.Fatalf("downloaded metadata changed: %+v %v", downloaded, err)
			}
		}
	}
}

func TestAssetsAndShutdown(t *testing.T) {
	server := testServer(t, runnerFunc(func(_ context.Context, request Request) (Result, error) { return fixtureResult(request), nil }))
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		response := perform(server, "GET", path, "")
		if response.Code != http.StatusOK || response.Body.Len() == 0 || !strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("asset %s = %d", path, response.Code)
		}
	}
	for _, path := range []string{"/../../go.mod", "/go.mod", "/assets/", "/api/jobs/unknown"} {
		if perform(server, "GET", path, "").Code != http.StatusNotFound {
			t.Fatalf("unexpected file route %s", path)
		}
	}
	server.Close()
	if perform(server, "POST", "/api/jobs", `{"kind":"recon","targets":["example.com"]}`).Code != http.StatusServiceUnavailable {
		t.Fatal("closed server accepted work")
	}
	for _, address := range []string{"0.0.0.0:8788", "localhost:8788", "127.0.0.1:0", "[::]:8788"} {
		if _, err := NewServer(context.Background(), server.runner, "0.2.0", address); err == nil {
			t.Fatalf("accepted non-bound loopback address %s", address)
		}
	}
}
