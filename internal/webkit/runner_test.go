package webkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

func runnerRequest() Request {
	return Request{Kind: "scan", Targets: []string{"https://company.example/path"}, DNS: true, TimeoutMS: 1000, Concurrency: 2, FailOn: "high"}
}

func enrichedObservation(target, observedAt string) inspect.Observation {
	parsed, _ := url.Parse(target)
	return inspect.Observation{
		URL: target, Hostname: parsed.Hostname(), Address: "93.184.215.14", Addresses: []string{"93.184.215.14"}, ObservedAt: observedAt,
		TLS: &inspect.TLSObservation{Authorized: true, Protocol: "TLSv1.3", ValidTo: "2027-01-01T00:00:00Z",
			ValidFrom: "2026-01-01T00:00:00Z", Subject: "CN=company.example", Issuer: "CN=Fixture issuer",
			DNSNames: []string{"company.example"}, FingerprintSHA256: strings.Repeat("ab", 32), SerialNumber: "123456",
			SignatureAlgorithm: "ECDSA-SHA256", PublicKeyAlgorithm: "ECDSA", PublicKeyBits: 256,
			CipherSuite: "TLS_AES_128_GCM_SHA256", NegotiatedProtocol: "http/1.1", VerifiedChainLength: 2},
		HTTP: &inspect.HTTPObservation{Status: 200, Headers: map[string][]string{"content-type": {"text/html"}},
			Cookies: &inspect.CookieObservation{Status: "ok", Total: 1, Items: []inspect.CookieAttributes{{Index: 1, Name: "session", Secure: true, HTTPOnly: true, SameSite: "lax", PathRoot: true}}}},
		DNS: &inspect.DNSObservation{
			A: inspect.DNSResult{Status: "ok", Records: []string{"93.184.215.14"}}, AAAA: inspect.DNSResult{Status: "absent", Records: []string{}},
			SPF: inspect.DNSResult{Status: "absent", Records: []string{}}, DMARC: inspect.DNSResult{Status: "absent", Records: []string{}}, MX: inspect.DNSResult{Status: "absent", Records: []string{}},
			NS: &inspect.DNSResult{Status: "ok", Records: []string{"ns1.company.example"}}, CNAME: &inspect.DNSResult{Status: "ok", Records: []string{"edge.company.example"}}},
		SecurityTXT: &inspect.SecurityTXTObservation{URL: "https://" + parsed.Hostname() + "/.well-known/security.txt", Status: "present", HTTPStatus: 200,
			ContactCount: 1, Expires: "2027-01-01T00:00:00Z", CanonicalPresent: true, CanonicalMatches: true, Issues: []string{}},
	}
}

func helperCommand(mode, capture string) commandFactory {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestRunnerHelperProcess$", "--"}, args...)...)
		command.Env = append(os.Environ(), "INSPECTYN_RUNNER_HELPER="+mode, "INSPECTYN_RUNNER_CAPTURE="+capture)
		return command
	}
}

func testedRunner(t *testing.T, mode string) (*CLIRunner, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	capture := filepath.Join(root, "capture.json")
	runner, err := newCLIRunner(self, helperCommand(mode, capture))
	if err != nil {
		t.Fatal(err)
	}
	runner.tempRoot = filepath.Join(root, "configuration")
	if err := os.Mkdir(runner.tempRoot, 0700); err != nil {
		t.Fatal(err)
	}
	return runner, capture
}

func assertTempCleaned(t *testing.T, runner *CLIRunner) {
	t.Helper()
	entries, err := os.ReadDir(runner.tempRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary configuration was not removed: %v %v", entries, err)
	}
}

type helperCapture struct {
	Args       []string       `json:"args"`
	Config     inspect.Config `json:"config"`
	ConfigPath string         `json:"configPath"`
	FileMode   uint32         `json:"fileMode"`
	DirMode    uint32         `json:"dirMode"`
}

func TestRunnerProbeAndSuccessfulRunUseFixedArgumentVector(t *testing.T) {
	runner, capturePath := testedRunner(t, "enriched")
	if runner.Version() != inspect.Version {
		t.Fatalf("version = %q", runner.Version())
	}
	request := runnerRequest()
	request.DNSDetails, request.SecurityTXT = true, true
	request.Targets[0] = "https://company.example/$(touch%20test);echo"
	result, err := runner.Run(context.Background(), request)
	if err != nil || result.Report == nil || result.ExitCode != 0 {
		t.Fatalf("run = %+v, %v", result, err)
	}
	var capture helperCapture
	data, err := os.ReadFile(capturePath)
	if err != nil || json.Unmarshal(data, &capture) != nil {
		t.Fatalf("capture = %s, %v", data, err)
	}
	expected := []string{"scan", "--config", capture.ConfigPath, "--concurrency", "2", "--format", "json", "--fail-on", "high"}
	if !reflect.DeepEqual(capture.Args, expected) {
		t.Fatalf("unexpected CLI arguments: %v", capture.Args)
	}
	if strings.Contains(strings.Join(capture.Args, " "), "touch") || !reflect.DeepEqual(capture.Config.Targets, request.Targets) {
		t.Fatalf("target escaped the config boundary: %+v", capture)
	}
	if !capture.Config.DNS || !capture.Config.DNSDetails || !capture.Config.SecurityTXT || capture.Config.TimeoutMS != 1000 || capture.Config.SchemaVersion != 1 {
		t.Fatalf("config settings lost: %+v", capture.Config)
	}
	if runtime.GOOS != "windows" && (capture.FileMode != 0600 || capture.DirMode != 0700) {
		t.Fatalf("unsafe temporary permissions: file=%o dir=%o", capture.FileMode, capture.DirMode)
	}
	if _, err := os.Stat(capture.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("temporary config still exists: %v", err)
	}
	assertTempCleaned(t, runner)
}

func TestRequestOptionsAndPhaseBudget(t *testing.T) {
	request := runnerRequest()
	request.Targets = append(request.Targets, "https://company.example/other")
	if got := runDeadline(request); got != 14*time.Second {
		t.Fatalf("baseline deadline = %s", got)
	}
	request.DNSDetails, request.SecurityTXT = true, true
	validated, err := ValidateRequest(request)
	if err != nil || !validated.config().DNSDetails || !validated.config().SecurityTXT || validated.config().Concurrency != request.Concurrency {
		t.Fatalf("options were lost: %+v, %v", validated, err)
	}
	if got := runDeadline(request); got != 16*time.Second {
		t.Fatalf("security.txt deadline = %s", got)
	}
	request.Kind = "recon"
	request.Targets = []string{"company.example"}
	if _, err := ValidateRequest(request); err == nil || !strings.Contains(err.Error(), "HTTPS scans only") {
		t.Fatalf("recon accepted an HTTPS check: %v", err)
	}
	request.SecurityTXT = false
	if validated, err := ValidateRequest(request); err != nil || !validated.DNSDetails {
		t.Fatalf("recon rejected DNS details: %+v, %v", validated, err)
	}
}

func TestRunnerPreservesExpandedObservations(t *testing.T) {
	runner, _ := testedRunner(t, "enriched")
	request := runnerRequest()
	request.DNSDetails, request.SecurityTXT = true, true
	result, err := runner.Run(context.Background(), request)
	if err != nil || result.Report == nil || result.ExitCode != 0 {
		t.Fatalf("enriched run = %+v, %v", result, err)
	}
	want := enrichedObservation(request.Targets[0], result.Report.GeneratedAt)
	if len(result.Report.Observations) != 1 || !reflect.DeepEqual(result.Report.Observations[0], want) {
		t.Fatalf("observation metadata changed: %+v", result.Report.Observations)
	}
	assertTempCleaned(t, runner)
}

func TestDecoderRejectsMissingOrUnresolvedRequestedChecks(t *testing.T) {
	for _, scenario := range []string{"no-dns", "no-ns", "no-cname", "no-security-txt", "unrequested-dns", "dns-error", "dns-skipped", "security-error", "security-unassessed", "security-redirect", "cookie-error", "cookie-invalid", "cookie-count"} {
		t.Run(scenario, func(t *testing.T) {
			request := runnerRequest()
			request.DNSDetails, request.SecurityTXT, request.FailOn = true, true, "none"
			report := fixtureResult(request).Report
			observation := enrichedObservation(request.Targets[0], report.GeneratedAt)
			switch scenario {
			case "no-dns":
				observation.DNS = nil
			case "no-ns":
				observation.DNS.NS = nil
			case "no-cname":
				observation.DNS.CNAME = nil
			case "no-security-txt":
				observation.SecurityTXT = nil
			case "unrequested-dns":
				request.DNSDetails = false
			case "dns-error":
				observation.DNS.NS.Status = "error"
			case "dns-skipped":
				observation.DNS.CNAME.Status = "skipped"
			case "security-error", "security-unassessed", "security-redirect":
				observation.SecurityTXT.Status = strings.TrimPrefix(scenario, "security-")
			case "cookie-error":
				observation.HTTP.Cookies.Status = "error"
			case "cookie-invalid":
				observation.HTTP.Cookies.Invalid = 1
			case "cookie-count":
				observation.HTTP.Cookies.Total = 2
			}
			report.Observations = []inspect.Observation{observation}
			encoded, err := inspect.RenderReport(*report, "json")
			if err != nil {
				t.Fatal(err)
			}
			if result, err := decodeCLIReport(encoded, request, inspect.Version, 0); err == nil || result != nil {
				t.Fatalf("accepted incomplete evidence as a completed passing run: %+v, %v", result, err)
			}
		})
	}
}

func TestDecoderAcceptsIncompleteRunsBeforeOptionalPhases(t *testing.T) {
	for _, scenario := range []string{"blocked-address", "canceled", "unresolved-metadata"} {
		t.Run(scenario, func(t *testing.T) {
			request := runnerRequest()
			request.DNSDetails, request.SecurityTXT = true, true
			report := fixtureResult(request).Report
			report.Complete = false
			switch scenario {
			case "blocked-address":
				observation := enrichedObservation(request.Targets[0], report.GeneratedAt)
				observation.Address, observation.Addresses = "", []string{"127.0.0.1"}
				observation.DNS.A.Records = []string{"127.0.0.1"}
				observation.HTTP, observation.TLS, observation.SecurityTXT = nil, nil, nil
				report.Observations = []inspect.Observation{observation}
				report.Errors = []inspect.CheckError{{Target: request.Targets[0], Code: "DESTINATION_BLOCKED", Message: "The hostname resolves to a private address; no HTTPS request was made."}}
			case "canceled":
				report.Errors = []inspect.CheckError{{Target: request.Targets[0], Code: "CANCELED", Message: "The check was canceled."}}
			case "unresolved-metadata":
				observation := enrichedObservation(request.Targets[0], report.GeneratedAt)
				observation.DNS.NS.Status = "error"
				observation.HTTP.Cookies.Status = "error"
				observation.SecurityTXT.Status = "unassessed"
				report.Observations = []inspect.Observation{observation}
				report.Findings = []inspect.Finding{{RuleID: "TEST_UNASSESSED", Severity: "info", Title: "Incomplete metadata", Evidence: "A requested check did not complete.", Remediation: "Repeat the check.", Target: request.Targets[0], State: "Not assessable"}}
			}
			encoded, err := inspect.RenderReport(*report, "json")
			if err != nil {
				t.Fatal(err)
			}
			result, err := decodeCLIReport(encoded, request, inspect.Version, 2)
			if err != nil || result == nil || result.Complete {
				t.Fatalf("discarded legitimate incomplete result: %+v, %v", result, err)
			}
		})
	}
}

func TestDecoderAcceptsAssessedOptionalAbsenceAndInvalidFormat(t *testing.T) {
	for _, status := range []string{"absent", "invalid"} {
		t.Run(status, func(t *testing.T) {
			request := runnerRequest()
			request.DNSDetails, request.SecurityTXT = true, true
			report := fixtureResult(request).Report
			observation := enrichedObservation(request.Targets[0], report.GeneratedAt)
			observation.DNS.NS.Status, observation.DNS.NS.Records = "absent", []string{}
			observation.DNS.CNAME.Status, observation.DNS.CNAME.Records = "absent", []string{}
			observation.SecurityTXT.Status = status
			report.Observations = []inspect.Observation{observation}
			encoded, err := inspect.RenderReport(*report, "json")
			if err != nil {
				t.Fatal(err)
			}
			if result, err := decodeCLIReport(encoded, request, inspect.Version, 0); err != nil || result == nil {
				t.Fatalf("rejected completed assessment: %+v, %v", result, err)
			}
		})
	}
}

func TestDecoderRestrictsSecurityTXTAndRejectsRawCookieValues(t *testing.T) {
	for _, scenario := range []string{"unrequested", "recon", "other-origin", "other-path", "query", "fragment", "cookie-value"} {
		t.Run(scenario, func(t *testing.T) {
			request := runnerRequest()
			request.DNSDetails, request.SecurityTXT = true, true
			if scenario == "unrequested" {
				request.SecurityTXT = false
			}
			if scenario == "recon" {
				request.Kind, request.Targets, request.SecurityTXT = "recon", []string{"https://company.example/"}, false
			}
			report := fixtureResult(request).Report
			observation := enrichedObservation(request.Targets[0], report.GeneratedAt)
			switch scenario {
			case "recon":
				observation.HTTP, observation.TLS = nil, nil
			case "other-origin":
				observation.SecurityTXT.URL = "https://other.example/.well-known/security.txt"
			case "other-path":
				observation.SecurityTXT.URL = "https://company.example/security.txt"
			case "query":
				observation.SecurityTXT.URL += "?extra=true"
			case "fragment":
				observation.SecurityTXT.URL += "#extra"
			}
			report.Observations = []inspect.Observation{observation}
			encoded, err := inspect.RenderReport(*report, "json")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "cookie-value" {
				var body map[string]any
				if err := json.Unmarshal(encoded, &body); err != nil {
					t.Fatal(err)
				}
				observed := body["observations"].([]any)[0].(map[string]any)
				cookie := observed["http"].(map[string]any)["cookies"].(map[string]any)["items"].([]any)[0].(map[string]any)
				cookie["value"] = "SECRET_COOKIE_VALUE"
				encoded, _ = json.Marshal(body)
			}
			if got, err := decodeCLIReport(encoded, request, inspect.Version, 0); err == nil || got != nil || strings.Contains(err.Error(), "SECRET_COOKIE_VALUE") {
				t.Fatalf("accepted out-of-scope or unexpected metadata: %+v, %v", got, err)
			}
		})
	}
}

func TestRunnerPreservesReportsForFindingAndIncompleteExitCodes(t *testing.T) {
	for mode, want := range map[string]int{"finding": 1, "incomplete": 2} {
		t.Run(mode, func(t *testing.T) {
			runner, _ := testedRunner(t, mode)
			result, err := runner.Run(context.Background(), runnerRequest())
			if err != nil || result.Report == nil || result.ExitCode != want {
				t.Fatalf("run = %+v, %v", result, err)
			}
			assertTempCleaned(t, runner)
		})
	}
}

func TestRunnerCanonicalizesReconWithoutEndpointObservations(t *testing.T) {
	runner, _ := testedRunner(t, "ok")
	request := runnerRequest()
	request.Kind, request.Targets, request.DNS = "recon", []string{"COMPANY.example"}, false
	result, err := runner.Run(context.Background(), request)
	if err != nil || result.ExitCode != 0 || result.Report.Kind != "recon" || result.Report.Targets[0] != "https://company.example/" {
		t.Fatalf("recon result = %+v, %v", result, err)
	}
	assertTempCleaned(t, runner)
}

func TestRunnerRejectsReportsThatDoNotMatchRunOrGate(t *testing.T) {
	for _, mode := range []string{"wrong-kind", "wrong-target", "wrong-order", "wrong-version", "wrong-tool", "outside-finding", "outside-error", "outside-observation", "duplicate-observation", "missing-result", "bad-severity", "exit-mismatch", "exit-unexpected", "no-report", "bad-json", "extra-json", "unknown-field", "null-array", "invalid-utf8", "wrong-coverage", "missing-coverage"} {
		t.Run(mode, func(t *testing.T) {
			runner, _ := testedRunner(t, mode)
			request := runnerRequest()
			request.Targets = append(request.Targets, "https://second.example/")
			result, err := runner.Run(context.Background(), request)
			if err == nil || result.Report != nil || strings.Contains(err.Error(), "SECRET_STDERR") || strings.Contains(err.Error(), "SECRET_JSON") {
				t.Fatalf("accepted invalid result or exposed subprocess output: %+v, %v", result, err)
			}
			assertTempCleaned(t, runner)
		})
	}
}

func TestRunnerRejectsRequestInjectionBeforeSubprocessStarts(t *testing.T) {
	runner, _ := testedRunner(t, "ok")
	started := false
	runner.command = func(context.Context, string, ...string) *exec.Cmd {
		started = true
		t.Fatal("invalid request started a subprocess")
		return nil
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Kind = "scan; command" },
		func(r *Request) { r.Kind = "--help" },
		func(r *Request) { r.Kind = "review" },
		func(r *Request) { r.Kind, r.SecurityTXT = "recon", true },
		func(r *Request) { r.FailOn = "high --out injected" },
		func(r *Request) { r.Targets = []string{"--config=untrusted"} },
		func(r *Request) { r.Targets = []string{"https://company.example\n--no-dns"} },
		func(r *Request) { r.Concurrency = 0 },
	} {
		request := runnerRequest()
		edit(&request)
		if _, err := runner.Run(context.Background(), request); err == nil {
			t.Fatalf("accepted request %+v", request)
		}
	}
	if started {
		t.Fatal("invalid request launched CLI")
	}
	assertTempCleaned(t, runner)
}

func TestRunnerCancellationKillsChildAndRemovesConfiguration(t *testing.T) {
	runner, _ := testedRunner(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := runner.Run(ctx, runnerRequest())
	if !errors.Is(err, context.DeadlineExceeded) || result.Report != nil || time.Since(started) > 3*time.Second {
		t.Fatalf("cancellation = %+v %v after %s", result, err, time.Since(started))
	}
	assertTempCleaned(t, runner)
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err = runner.Run(ctx, runnerRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("already-canceled request: %v", err)
	}
	assertTempCleaned(t, runner)
}

func TestRunnerBoundsBothOutputStreamsAndCleansUp(t *testing.T) {
	for _, mode := range []string{"stdout-overflow", "stderr-overflow"} {
		t.Run(mode, func(t *testing.T) {
			runner, _ := testedRunner(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := time.Now()
			result, err := runner.Run(ctx, runnerRequest())
			if err == nil || !strings.Contains(err.Error(), "output limit") || result.Report != nil || time.Since(started) > 3*time.Second {
				t.Fatalf("output bound = %+v, %v", result, err)
			}
			assertTempCleaned(t, runner)
		})
	}
}

func TestVersionProbeRejectsUnexpectedAndExcessiveOutput(t *testing.T) {
	for _, mode := range []string{"bad-version", "version-overflow", "version-exit"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := probeCLI(context.Background(), "unused", helperCommand(mode, "")); err == nil || strings.Contains(err.Error(), "SECRET_STDERR") {
				t.Fatalf("invalid version response accepted or leaked: %v", err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := probeCLI(ctx, "unused", helperCommand("version-hang", "")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unbounded version probe: %v", err)
	}
}

func TestStartupRejectsMismatchedCLIVersion(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCLIRunner(self, helperCommand("old-version", "")); err == nil || !strings.Contains(err.Error(), "does not match web version "+inspect.Version) || !strings.Contains(err.Error(), "build both executables") {
		t.Fatalf("version mismatch was not actionable: %v", err)
	}
}

func TestExecutableResolutionPrefersExplicitThenSiblingThenPATH(t *testing.T) {
	root := t.TempDir()
	name := "inspectyn"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	sibling := filepath.Join(root, name)
	explicit := filepath.Join(root, "explicit.exe")
	pathBinary := filepath.Join(root, "from-path.exe")
	for _, file := range []string{sibling, explicit, pathBinary} {
		if err := os.WriteFile(file, []byte("fixture"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	lookups := 0
	lookup := func(got string) (string, error) {
		lookups++
		if got != name {
			t.Fatalf("lookup name: %q", got)
		}
		return pathBinary, nil
	}
	self := filepath.Join(root, "inspectyn-web.exe")
	got, err := findCLI(explicit, self, lookup)
	if err != nil || got != explicit || lookups != 0 {
		t.Fatalf("explicit path = %q, %v", got, err)
	}
	got, err = findCLI("", self, lookup)
	if err != nil || got != sibling || lookups != 0 {
		t.Fatalf("sibling path = %q, %v", got, err)
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}
	got, err = findCLI("", self, lookup)
	if err != nil || got != pathBinary || lookups != 1 {
		t.Fatalf("PATH resolution = %q, %v", got, err)
	}
	if _, err := findCLI(filepath.Join(root, "missing.exe"), self, lookup); err == nil || lookups != 1 {
		t.Fatal("missing explicit path silently fell back to PATH")
	}
	if _, err := findCLI(root, self, lookup); err == nil {
		t.Fatal("accepted directory as CLI")
	}
}

func TestRunnerHelperProcess(t *testing.T) {
	mode := os.Getenv("INSPECTYN_RUNNER_HELPER")
	if mode == "" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	hang := func() {
		for {
			time.Sleep(time.Second)
		}
	}
	if len(args) == 1 && args[0] == "--version" {
		switch mode {
		case "old-version":
			fmt.Fprintln(os.Stdout, "0.2.0")
			os.Exit(0)
		case "bad-version":
			fmt.Fprint(os.Stdout, "SECRET_STDERR unexpected version")
			os.Exit(0)
		case "version-overflow":
			_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), runnerProbeLimit+1))
			hang()
		case "version-exit":
			fmt.Fprintln(os.Stdout, inspect.Version)
			os.Exit(2)
		case "version-hang":
			hang()
		}
		fmt.Fprintln(os.Stdout, inspect.Version)
		os.Exit(0)
	}
	if len(args) != 9 || args[1] != "--config" {
		os.Exit(7)
	}
	configPath := args[2]
	data, err := os.ReadFile(configPath)
	if err != nil {
		os.Exit(8)
	}
	var config inspect.Config
	if json.Unmarshal(data, &config) != nil {
		os.Exit(9)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		os.Exit(10)
	}
	dirInfo, err := os.Stat(filepath.Dir(configPath))
	if err != nil {
		os.Exit(11)
	}
	if capturePath := os.Getenv("INSPECTYN_RUNNER_CAPTURE"); capturePath != "" {
		capture, _ := json.Marshal(helperCapture{Args: args, Config: config, ConfigPath: configPath, FileMode: uint32(info.Mode().Perm()), DirMode: uint32(dirInfo.Mode().Perm())})
		if os.WriteFile(capturePath, capture, 0600) != nil {
			os.Exit(12)
		}
	}
	switch mode {
	case "hang":
		hang()
	case "stdout-overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), runnerStdoutLimit+1))
		hang()
	case "stderr-overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("x"), runnerStderrLimit+1))
		hang()
	case "no-report":
		fmt.Fprintln(os.Stderr, "SECRET_STDERR")
		os.Exit(2)
	case "bad-json":
		fmt.Fprintln(os.Stdout, "SECRET_JSON")
		fmt.Fprintln(os.Stderr, "SECRET_STDERR")
		os.Exit(2)
	case "invalid-utf8":
		_, _ = os.Stdout.Write([]byte{0xff, 0xfe})
		os.Exit(0)
	}
	report := inspect.Report{SchemaVersion: 1, Tool: inspect.Tool{Name: "inspectyn", Version: inspect.Version}, Kind: args[0], GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Complete: true, Targets: config.Targets, Findings: []inspect.Finding{}, Errors: []inspect.CheckError{}, Observations: []inspect.Observation{}, Context: map[string]any{}}
	for _, target := range config.Targets {
		parsed, _ := url.Parse(target)
		report.Observations = append(report.Observations, inspect.Observation{URL: target, Hostname: parsed.Hostname(), Addresses: []string{}, ObservedAt: report.GeneratedAt})
	}
	finding := inspect.Finding{Target: config.Targets[0], RuleID: "TEST_FINDING", Severity: "high", Title: "Test finding", Evidence: "Supplied test evidence", Remediation: "Review test evidence"}
	code := 0
	switch mode {
	case "enriched":
		report.Observations[0] = enrichedObservation(config.Targets[0], report.GeneratedAt)
	case "finding":
		report.Findings = append(report.Findings, finding)
		code = 1
	case "incomplete":
		report.Complete = false
		report.Errors = append(report.Errors, inspect.CheckError{Target: config.Targets[0], Code: "TEST_INCOMPLETE", Message: "Incomplete test observation"})
		code = 2
	case "wrong-kind":
		report.Kind = "review"
	case "wrong-target":
		report.Targets = []string{"https://unrequested.example/"}
	case "wrong-order":
		report.Targets = append([]string{}, report.Targets...)
		report.Targets[0], report.Targets[1] = report.Targets[1], report.Targets[0]
	case "wrong-version":
		report.Tool.Version = "99.0.0"
	case "wrong-tool":
		report.Tool.Name = "other"
	case "outside-finding":
		finding.Target = "https://unrequested.example/"
		report.Findings = append(report.Findings, finding)
		code = 1
	case "outside-error":
		report.Complete = false
		report.Errors = append(report.Errors, inspect.CheckError{Target: "https://unrequested.example/", Code: "TEST", Message: "Test"})
		code = 2
	case "outside-observation":
		report.Observations[0].URL = "https://unrequested.example/"
	case "duplicate-observation":
		report.Observations = append(report.Observations, report.Observations[0])
	case "missing-result":
		report.Observations = []inspect.Observation{}
	case "bad-severity":
		finding.Severity = "invented"
		report.Findings = append(report.Findings, finding)
	case "exit-mismatch":
		code = 1
	case "exit-unexpected":
		code = 7
	case "null-array":
		report.Findings = nil
	}
	encoded, renderErr := inspect.RenderReport(report, "json")
	if renderErr != nil {
		encoded, _ = json.Marshal(report)
	}
	encoded = bytes.TrimSpace(encoded)
	if mode == "null-array" || mode == "wrong-coverage" || mode == "missing-coverage" {
		var body map[string]any
		_ = json.Unmarshal(encoded, &body)
		switch mode {
		case "null-array":
			body["findings"] = nil
		case "wrong-coverage":
			body["coverage"].(map[string]any)["status"] = "incomplete"
		case "missing-coverage":
			delete(body, "coverage")
		}
		encoded, _ = json.Marshal(body)
	}
	if mode == "unknown-field" {
		encoded = append(encoded[:len(encoded)-1], []byte(`,"unexpected":"SECRET_JSON"}`)...)
	}
	_, _ = os.Stdout.Write(encoded)
	if mode == "extra-json" {
		fmt.Fprintln(os.Stdout, "{}")
	}
	os.Exit(code)
}
