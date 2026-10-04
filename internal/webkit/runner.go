package webkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

const runnerStdoutLimit = 10 * 1024 * 1024
const runnerStderrLimit = 64 * 1024
const runnerProbeLimit = 4096
const runnerProbeTimeout = 5 * time.Second
const runnerWaitDelay = 500 * time.Millisecond

type commandFactory func(context.Context, string, ...string) *exec.Cmd

type CLIRunner struct {
	path     string
	version  string
	command  commandFactory
	tempRoot string
}

var cliVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

func NewCLIRunner(path string) (*CLIRunner, error) {
	return newCLIRunner(path, exec.CommandContext)
}

func newCLIRunner(path string, command commandFactory) (*CLIRunner, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, errors.New("could not locate the web UI executable")
	}
	resolved, err := findCLI(path, self, exec.LookPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), runnerProbeTimeout)
	defer cancel()
	version, err := probeCLI(ctx, resolved, command)
	if err != nil {
		return nil, err
	}
	return &CLIRunner{path: resolved, version: version, command: command}, nil
}

func findCLI(explicit, self string, lookup func(string) (string, error)) (string, error) {
	name := "inspectyn"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	selected := explicit
	if selected == "" {
		selected = filepath.Join(filepath.Dir(self), name)
		if _, err := os.Stat(selected); err != nil {
			if !os.IsNotExist(err) {
				return "", errors.New("could not access the sibling Inspectyn CLI")
			}
			selected, err = lookup(name)
			if err != nil {
				return "", errors.New("Inspectyn CLI not found; specify its executable path")
			}
		}
	}
	absolute, err := filepath.Abs(selected)
	if err != nil {
		return "", errors.New("invalid Inspectyn CLI executable path")
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
		return "", errors.New("Inspectyn CLI path must identify an executable file")
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(absolute), ".exe") {
		return "", errors.New("Inspectyn CLI path must identify an .exe file")
	}
	return absolute, nil
}

func (r *CLIRunner) Version() string { return r.version }

// Each stream has an independent byte budget. Cancellation kills a child that
// keeps writing; WaitDelay also bounds pipes inherited by a descendant process.
type boundedOutput struct {
	mu       sync.Mutex
	data     bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.data.Len()
	if len(p) > remaining {
		if remaining > 0 {
			_, _ = b.data.Write(p[:remaining])
		}
		b.exceeded = true
		b.cancel()
		return len(p), nil
	}
	_, _ = b.data.Write(p)
	return len(p), nil
}

func (b *boundedOutput) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data.Bytes()...), b.exceeded
}

func executeCLI(ctx context.Context, path string, args []string, command commandFactory, stdoutLimit, stderrLimit int) ([]byte, int, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &boundedOutput{limit: stdoutLimit, cancel: cancel}
	stderr := &boundedOutput{limit: stderrLimit, cancel: cancel}
	cmd := command(childCtx, path, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = runnerWaitDelay
	err := cmd.Run()
	output, stdoutExceeded := stdout.snapshot()
	_, stderrExceeded := stderr.snapshot()
	if ctx.Err() != nil {
		return nil, 2, fmt.Errorf("Inspectyn CLI execution stopped: %w", ctx.Err())
	}
	if stdoutExceeded || stderrExceeded {
		return nil, 2, errors.New("Inspectyn CLI exceeded its output limit")
	}
	if err == nil {
		return output, 0, nil
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) && (exited.ExitCode() == 1 || exited.ExitCode() == 2) {
		return output, exited.ExitCode(), nil
	}
	return nil, 2, errors.New("Inspectyn CLI failed to execute or exited unexpectedly")
}

func probeCLI(ctx context.Context, path string, command commandFactory) (string, error) {
	output, code, err := executeCLI(ctx, path, []string{"--version"}, command, runnerProbeLimit, runnerProbeLimit)
	if err != nil {
		return "", fmt.Errorf("Inspectyn CLI version check failed: %w", err)
	}
	version := strings.TrimSpace(string(output))
	if code != 0 || len(version) > 80 || !cliVersion.MatchString(version) {
		return "", errors.New("Inspectyn CLI returned an unsupported version response")
	}
	if version != inspect.Version {
		return "", fmt.Errorf("Inspectyn CLI version %s does not match web version %s; build both executables from the same version", version, inspect.Version)
	}
	return version, nil
}

func (r *CLIRunner) Run(ctx context.Context, request Request) (result Result, runErr error) {
	request, err := ValidateRequest(request)
	if err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("Inspectyn CLI execution stopped: %w", ctx.Err())
	}
	dir, err := os.MkdirTemp(r.tempRoot, "inspectyn-web-")
	if err != nil {
		return Result{}, errors.New("could not create a temporary CLI configuration")
	}
	configPath := filepath.Join(dir, "inspectyn.json")
	defer func() {
		removeErr := os.Remove(configPath)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			result, runErr = Result{}, errors.New("could not remove the temporary CLI configuration")
		}
		if err := os.Remove(dir); err != nil {
			result, runErr = Result{}, errors.New("could not remove the temporary CLI configuration directory")
		}
	}()
	config := request.config()
	encoded, err := json.Marshal(config)
	if err != nil {
		return Result{}, errors.New("could not encode the CLI configuration")
	}
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Result{}, errors.New("could not write the temporary CLI configuration")
	}
	_, writeErr := file.Write(append(encoded, '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return Result{}, errors.New("could not write the temporary CLI configuration")
	}
	args := []string{request.Kind, "--config", configPath, "--concurrency", strconv.Itoa(request.Concurrency), "--format", "json", "--fail-on", request.FailOn}
	output, code, err := executeCLI(ctx, r.path, args, r.command, runnerStdoutLimit, runnerStderrLimit)
	if err != nil {
		return Result{}, err
	}
	report, err := decodeCLIReport(output, request, r.version, code)
	if err != nil {
		return Result{}, err
	}
	return Result{Report: report, ExitCode: code}, nil
}

func decodeCLIReport(data []byte, request Request, version string, exitCode int) (*inspect.Report, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("Inspectyn CLI returned an invalid report")
	}
	type coverage struct {
		Status    string `json:"status"`
		Statement string `json:"statement"`
	}
	var envelope struct {
		inspect.Report
		Coverage *coverage `json:"coverage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		return nil, errors.New("Inspectyn CLI returned an invalid report")
	}
	report := envelope.Report
	var extra any
	if decoder.Decode(&extra) != io.EOF || envelope.Coverage == nil || report.Targets == nil || report.Findings == nil || report.Errors == nil || report.Observations == nil {
		return nil, errors.New("Inspectyn CLI returned an invalid report")
	}
	if report.Tool.Name != "inspectyn" || report.Tool.Version != version || report.Kind != request.Kind || !slices.Equal(report.Targets, request.Targets) {
		return nil, errors.New("Inspectyn CLI report does not match the requested run")
	}
	scope := make(map[string]string, len(request.Targets))
	for _, target := range request.Targets {
		parsed, _ := url.Parse(target)
		scope[target] = parsed.Hostname()
	}
	for _, finding := range report.Findings {
		if _, ok := scope[finding.Target]; !ok {
			return nil, errors.New("Inspectyn CLI report includes a finding outside the requested scope")
		}
	}
	for _, failure := range report.Errors {
		if _, ok := scope[failure.Target]; !ok {
			return nil, errors.New("Inspectyn CLI report includes an error outside the requested scope")
		}
	}
	observed := make(map[string]bool, len(report.Observations))
	for _, observation := range report.Observations {
		hostname, ok := scope[observation.URL]
		if !ok || hostname != observation.Hostname || observed[observation.URL] || (request.Kind == "recon" && (observation.HTTP != nil || observation.TLS != nil || observation.SecurityTXT != nil)) {
			return nil, errors.New("Inspectyn CLI report includes inconsistent observations")
		}
		if observation.SecurityTXT != nil {
			resource := (&url.URL{Scheme: "https", Host: hostname, Path: "/.well-known/security.txt"}).String()
			if !request.SecurityTXT || observation.SecurityTXT.URL != resource {
				return nil, errors.New("Inspectyn CLI report includes security.txt outside the requested scope")
			}
		}
		if err := validateObservationCoverage(observation, request, report.Complete); err != nil {
			return nil, err
		}
		observed[observation.URL] = true
	}
	covered := make(map[string]bool, len(observed))
	for target := range observed {
		covered[target] = true
	}
	for _, failure := range report.Errors {
		covered[failure.Target] = true
	}
	if len(covered) != len(request.Targets) {
		return nil, errors.New("Inspectyn CLI report omits a requested target's result")
	}
	expectedCode, err := inspect.ReportExitCode(report, request.FailOn)
	if err != nil {
		return nil, errors.New("Inspectyn CLI returned an invalid report")
	}
	if expectedCode != exitCode {
		return nil, errors.New("Inspectyn CLI exit status does not match its report")
	}
	// Downloads regenerate this renderer-owned metadata from the validated report.
	rendered, err := inspect.RenderReport(report, "json")
	if err != nil {
		return nil, errors.New("Inspectyn CLI returned an invalid report")
	}
	var expected struct {
		Coverage coverage `json:"coverage"`
	}
	if json.Unmarshal(rendered, &expected) != nil || *envelope.Coverage != expected.Coverage {
		return nil, errors.New("Inspectyn CLI report contains inconsistent coverage metadata")
	}
	return &report, nil
}

func validateObservationCoverage(observation inspect.Observation, request Request, complete bool) error {
	dns := observation.DNS
	if !request.DNSDetails && dns != nil && (dns.NS != nil || dns.CNAME != nil) {
		return errors.New("Inspectyn CLI report includes DNS details that were not requested")
	}
	if !complete {
		return nil
	}
	if request.DNSDetails && (dns == nil || dns.NS == nil || dns.CNAME == nil) || request.SecurityTXT && observation.SecurityTXT == nil {
		return errors.New("Inspectyn CLI report marks an omitted requested check as complete")
	}
	if request.DNSDetails {
		for _, result := range []*inspect.DNSResult{dns.NS, dns.CNAME} {
			if result.Status != "ok" && result.Status != "absent" {
				return errors.New("Inspectyn CLI report marks unresolved DNS details as complete")
			}
		}
	}
	if securityTXT := observation.SecurityTXT; securityTXT != nil {
		switch securityTXT.Status {
		case "present", "absent", "invalid":
		default:
			return errors.New("Inspectyn CLI report marks unresolved security.txt evidence as complete")
		}
	}
	if observation.HTTP != nil && observation.HTTP.Cookies != nil {
		cookies := observation.HTTP.Cookies
		if cookies.Status != "ok" || cookies.Invalid != 0 || cookies.Total != len(cookies.Items) {
			return errors.New("Inspectyn CLI report marks unresolved cookie evidence as complete")
		}
	}
	return nil
}
