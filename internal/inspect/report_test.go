package inspect

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func sampleReport() Report {
	return Report{SchemaVersion: 1, Tool: Tool{Name: "inspectyn", Version: Version}, Kind: "scan", GeneratedAt: "2026-10-03T00:00:00Z", Complete: true,
		Targets: []string{"https://example.com/"}, Findings: []Finding{{RuleID: "SPECTYN_TEST", Severity: "high", Title: "Review candidate", Target: "https://example.com/", Evidence: "Observed evidence", Remediation: "Review configuration"}},
		Errors: []CheckError{}, Observations: []Observation{checkFixtureObservation()}, Context: map[string]any{"scope": "Explicit targets only"},
	}
}

func assertReportCode(t *testing.T, report Report, failOn string, want int) {
	t.Helper()
	got, err := ReportExitCode(report, failOn)
	if err != nil || got != want {
		t.Fatalf("exit code = %d (%v), want %d", got, err, want)
	}
}

func TestReportSeverityGateAndUnknownConfidence(t *testing.T) {
	report := sampleReport()
	assertReportCode(t, report, "high", 1)
	assertReportCode(t, report, "", 1)
	assertReportCode(t, report, "critical", 0)
	assertReportCode(t, report, "none", 0)
	for _, state := range []string{"Observed", "Not applicable"} {
		report.Findings[0].State = state
		assertReportCode(t, report, "info", 0)
	}
	report.Findings[0].State = "Needs review"
	report.Findings[0].Severity = "unknown"
	assertReportCode(t, report, "critical", 2)
	assertReportCode(t, report, "none", 0)
	report.Findings[0].State = "Observed"
	assertReportCode(t, report, "info", 0)
	for _, threshold := range []string{"unknown", "HIGH", "invalid"} {
		if code, err := ReportExitCode(report, threshold); code != 2 || err == nil {
			t.Fatalf("invalid gate %q accepted: %d, %v", threshold, code, err)
		}
	}
}

func TestIncompleteEvidenceNeverReturnsClean(t *testing.T) {
	for _, change := range []func(*Report){
		func(report *Report) { report.Complete = false },
		func(report *Report) {
			report.Errors = []CheckError{{Target: "example.com", Code: "DNS_FAILED", Message: "Lookup failed"}}
		},
		func(report *Report) { report.Findings[0].State = "Not assessable" },
	} {
		report := sampleReport()
		change(&report)
		for _, threshold := range []string{"none", "critical", "low"} {
			assertReportCode(t, report, threshold, 2)
		}
		for _, format := range []string{"text", "markdown", "html"} {
			data, err := RenderReport(report, format)
			if err != nil || !strings.Contains(string(data), "INCOMPLETE") {
				t.Fatalf("%s hides incomplete evidence: %v", format, err)
			}
		}
		data, _ := RenderReport(report, "json")
		var decoded struct {
			Coverage struct {
				Status string `json:"status"`
			} `json:"coverage"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.Coverage.Status != "incomplete" {
			t.Fatal("JSON coverage hides incompleteness")
		}
	}
}

func TestReportValidationAndKinds(t *testing.T) {
	for _, kind := range []string{"scan", "recon", "review"} {
		report := sampleReport()
		report.Kind = kind
		if _, err := RenderReport(report, "json"); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*Report){
		func(report *Report) { report.SchemaVersion = 2 },
		func(report *Report) { report.Tool.Name = "other" },
		func(report *Report) { report.Kind = "other" },
		func(report *Report) { report.GeneratedAt = "yesterday" },
		func(report *Report) { report.Findings[0].Severity = "severe" },
		func(report *Report) { report.Findings[0].State = "safe" },
		func(report *Report) { report.Findings[0].Title = "" },
		func(report *Report) { report.Context = map[string]any{"nan": math.NaN()} },
		func(report *Report) { report.Context = map[string]any{}; report.Context["self"] = report.Context },
		func(report *Report) { report.Findings[0].Evidence = strings.Repeat("x", 16385) },
	} {
		report := sampleReport()
		change(&report)
		if _, err := RenderReport(report, "text"); err == nil {
			t.Fatal("invalid report accepted")
		}
		if code, err := ReportExitCode(report, "none"); code != 2 || err == nil {
			t.Fatal("invalid report passed disabled gate")
		}
	}
	if _, err := RenderReport(sampleReport(), "csv"); err == nil {
		t.Fatal("unsupported format accepted")
	}
}

func TestHTMLAutoescapesAndHasNoExecutableContent(t *testing.T) {
	report := sampleReport()
	attack := `<script>alert(1)</script><img src="https://evil.example/x" onerror="alert(1)">`
	report.Findings[0].Title, report.Findings[0].Evidence = attack, attack
	report.Context["payload"] = attack
	report.Observations[0].HTTP.Headers["content-security-policy"] = []string{attack}
	data, err := RenderReport(report, "html")
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	if strings.Contains(output, "<script") || strings.Contains(output, "<img") || strings.Contains(output, "<iframe") {
		t.Fatal("HTML contains injected markup")
	}
	if !strings.Contains(output, "&lt;script&gt;") || !strings.Contains(output, "default-src 'none'") {
		t.Fatal("missing HTML escaping or resource policy")
	}
	if !strings.Contains(output, "Source and observation context") || !strings.Contains(output, "content-security-policy") {
		t.Fatal("HTML lost observation evidence")
	}
}

func TestHumanFormatsStripControlsAndContainMarkdown(t *testing.T) {
	report := sampleReport()
	attack := "\x1b[31mRed\x1b[0m\x1b]8;;https://evil.example\x07link\x1b]8;;\x07\r\b\u202e <img src=x> [visit](https://evil.example)\n# forged"
	report.Findings[0].Evidence = attack
	report.Context["payload"] = attack + "\n```\n# injected fence"
	for _, format := range []string{"text", "markdown", "html"} {
		data, err := RenderReport(report, format)
		if err != nil {
			t.Fatal(err)
		}
		output := string(data)
		if strings.ContainsAny(output, "\x1b\r\b\u202e") || strings.Contains(output, `\u001b`) || strings.Contains(output, `\u202e`) {
			t.Fatalf("%s leaked terminal controls", format)
		}
		if !strings.Contains(output, "Red") || !strings.Contains(output, "link") {
			t.Fatal("sanitization erased readable evidence")
		}
		if format == "markdown" {
			prose, _, _ := strings.Cut(output, "## Source and observation context")
			if strings.Contains(prose, "[visit](https://evil.example)") || !strings.Contains(prose, `\[visit\]\(https://evil.example\)`) {
				t.Fatal("Markdown link injection was not escaped")
			}
			if !strings.Contains(output, "````json") {
				t.Fatal("metadata backticks can break the JSON fence")
			}
		}
	}
	data, _ := RenderReport(report, "json")
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Findings[0].Evidence != attack {
		t.Fatal("JSON must preserve original evidence strings")
	}
}

func TestReportPreservesDNSHeadersContextAndEmptyArrays(t *testing.T) {
	report := sampleReport()
	report.Kind = "recon"
	report.Findings, report.Errors = nil, nil
	report.Context["catalog"] = map[string]any{"version": "fixture-v1", "releasedAt": "2026-09-17"}
	for _, format := range []string{"json", "text", "markdown", "html"} {
		data, err := RenderReport(report, format)
		if err != nil {
			t.Fatal(err)
		}
		output := string(data)
		for _, detail := range []string{"fixture-v1", "2026-09-17", "v=spf1 -all", "strict-transport-security", "No findings is not assurance"} {
			if !strings.Contains(output, detail) {
				t.Fatalf("%s omits %q", format, detail)
			}
		}
		if format == "json" {
			var decoded map[string]any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"findings", "errors"} {
				if _, ok := decoded[name].([]any); !ok {
					t.Fatalf("%s should be an empty array", name)
				}
			}
		}
	}
}
