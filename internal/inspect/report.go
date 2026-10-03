package inspect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"time"
)

const reportCoverage = "This report covers only the supplied evidence or explicitly requested checks. No findings is not assurance that a target is secure. Observations and review candidates do not establish exploitability."
const maxReportBytes = 10 * 1024 * 1024

var reportSeverities = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": -1}
var reportStates = map[string]bool{"": true, "Needs review": true, "Observed": true, "Not assessable": true, "Not applicable": true}

func validateNativeReport(report Report) error {
	if report.SchemaVersion != 1 {
		return fmt.Errorf("invalid Inspectyn report: expected schemaVersion 1")
	}
	if report.Tool.Name != "inspectyn" && report.Tool.Name != "spectyn" {
		return fmt.Errorf("invalid Inspectyn report: unsupported tool name")
	}
	if strings.TrimSpace(report.Tool.Version) == "" || len(report.Tool.Version) > 80 {
		return fmt.Errorf("invalid Inspectyn report: tool version is missing or oversized")
	}
	if report.Kind != "scan" && report.Kind != "recon" && report.Kind != "review" {
		return fmt.Errorf("invalid Inspectyn report: kind must be scan, recon or review")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.GeneratedAt); err != nil {
		return fmt.Errorf("invalid Inspectyn report: generatedAt must be an ISO timestamp with a timezone")
	}
	for _, target := range report.Targets {
		if strings.TrimSpace(target) == "" || len(target) > 2048 {
			return fmt.Errorf("invalid Inspectyn report: target is empty or oversized")
		}
	}
	for _, finding := range report.Findings {
		if _, ok := reportSeverities[finding.Severity]; !ok {
			return fmt.Errorf("invalid Inspectyn report: unsupported finding severity")
		}
		if !reportStates[finding.State] {
			return fmt.Errorf("invalid Inspectyn report: unsupported finding state")
		}
		for _, field := range []struct {
			value string
			limit int
		}{{finding.RuleID, 256}, {finding.Title, 2048}, {finding.Target, 2048}} {
			if strings.TrimSpace(field.value) == "" || len(field.value) > field.limit {
				return fmt.Errorf("invalid Inspectyn report: a required finding field is empty or oversized")
			}
		}
		if len(finding.Evidence) > 16384 || len(finding.Remediation) > 16384 {
			return fmt.Errorf("invalid Inspectyn report: finding text is oversized")
		}
	}
	for _, item := range report.Errors {
		if strings.TrimSpace(item.Target) == "" || strings.TrimSpace(item.Code) == "" || strings.TrimSpace(item.Message) == "" {
			return fmt.Errorf("invalid Inspectyn report: error details are missing")
		}
		if len(item.Target) > 2048 || len(item.Code) > 256 || len(item.Message) > 16384 {
			return fmt.Errorf("invalid Inspectyn report: error details are oversized")
		}
	}
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("invalid Inspectyn report: context must contain finite, non-circular JSON values")
	}
	if len(data) > maxReportBytes {
		return fmt.Errorf("invalid Inspectyn report: serialized report exceeds 10 MiB")
	}
	return nil
}

func reportIncomplete(report Report) bool {
	if !report.Complete || len(report.Errors) > 0 {
		return true
	}
	for _, finding := range report.Findings {
		if finding.State == "Not assessable" {
			return true
		}
	}
	return false
}

func actionableFinding(finding Finding) bool {
	return finding.State == "" || finding.State == "Needs review"
}

// ReportExitCode returns 2 for incomplete evidence or an indeterminate enabled
// gate, 1 when an actionable finding meets the threshold, and 0 otherwise.
// Disabling severity gating never hides a failed or incomplete assessment.
func ReportExitCode(report Report, failOn string) (int, error) {
	if err := validateNativeReport(report); err != nil {
		return 2, err
	}
	if failOn == "" {
		failOn = "high"
	}
	threshold, valid := reportSeverities[failOn]
	if failOn != "none" && (!valid || failOn == "unknown") {
		return 2, fmt.Errorf("fail-on must be none, info, low, medium, high or critical")
	}
	if reportIncomplete(report) {
		return 2, nil
	}
	if failOn == "none" {
		return 0, nil
	}
	for _, finding := range report.Findings {
		if actionableFinding(finding) && finding.Severity == "unknown" {
			return 2, nil
		}
	}
	for _, finding := range report.Findings {
		if actionableFinding(finding) && reportSeverities[finding.Severity] >= threshold {
			return 1, nil
		}
	}
	return 0, nil
}

var (
	reportOSC    = regexp.MustCompile(`(?s)\x1b\].*?(?:\x07|\x1b\\|$)`)
	reportDCS    = regexp.MustCompile(`(?s)\x1b[P^_].*?(?:\x1b\\|$)`)
	reportCSI    = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	reportEscape = regexp.MustCompile(`\x1b[@-_]`)
)

func cleanReportText(value string) string {
	for _, pattern := range []*regexp.Regexp{reportOSC, reportDCS, reportCSI, reportEscape} {
		value = pattern.ReplaceAllString(value, "")
	}
	return strings.Map(func(ch rune) rune {
		if ch <= 8 || (ch >= 11 && ch <= 31) || (ch >= 127 && ch <= 159) || ch == 0x061c || ch == 0x200e || ch == 0x200f || (ch >= 0x202a && ch <= 0x202e) || (ch >= 0x2066 && ch <= 0x2069) {
			return -1
		}
		return ch
	}, value)
}

func reportLine(value string) string {
	return strings.Map(func(ch rune) rune {
		if ch == '\n' || ch == '\t' || ch == 0x2028 || ch == 0x2029 {
			return ' '
		}
		return ch
	}, cleanReportText(value))
}

func reportMarkdown(value string) string {
	var output strings.Builder
	for _, ch := range reportLine(value) {
		if strings.ContainsRune("\\`*_{}[]()<>#!|~", ch) {
			output.WriteByte('\\')
		}
		output.WriteRune(ch)
	}
	return output.String()
}

func sanitizedJSONValue(value any) any {
	switch item := value.(type) {
	case string:
		return cleanReportText(item)
	case []any:
		for i := range item {
			item[i] = sanitizedJSONValue(item[i])
		}
		return item
	case map[string]any:
		clean := make(map[string]any, len(item))
		for key, child := range item {
			clean[cleanReportText(key)] = sanitizedJSONValue(child)
		}
		return clean
	default:
		return value
	}
}

func reportContextJSON(report Report) (string, error) {
	data, err := json.Marshal(map[string]any{"context": report.Context, "observations": report.Observations})
	if err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return "", err
	}
	data, err = json.MarshalIndent(sanitizedJSONValue(value), "", "  ")
	return string(data), err
}

func reportStatus(report Report) string {
	if reportIncomplete(report) {
		return "INCOMPLETE - errors or evidence gaps require attention"
	}
	return "Complete for requested checks"
}

func displayFindingState(state string) string {
	if state == "" {
		return "Needs review"
	}
	return state
}

func renderNativeText(report Report, context string) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "INSPECTYN %s REPORT\nStatus: %s\nGenerated: %s | Inspectyn %s\nTargets: %d | Findings: %d | Errors: %d\n\n%s\n", strings.ToUpper(report.Kind), reportStatus(report), reportLine(report.GeneratedAt), reportLine(report.Tool.Version), len(report.Targets), len(report.Findings), len(report.Errors), reportCoverage)
	output.WriteString("\nTargets\n")
	for _, target := range report.Targets {
		fmt.Fprintf(&output, "  %s\n", reportLine(target))
	}
	output.WriteString("\nFindings\n")
	if len(report.Findings) == 0 {
		output.WriteString("  No findings were produced for this coverage.\n")
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&output, "  [%s] %s\n  Target: %s | Rule: %s | State: %s\n  Evidence: %s\n  Remediation: %s\n\n", strings.ToUpper(finding.Severity), reportLine(finding.Title), reportLine(finding.Target), reportLine(finding.RuleID), displayFindingState(finding.State), reportLine(finding.Evidence), reportLine(finding.Remediation))
	}
	if len(report.Errors) > 0 {
		output.WriteString("\nErrors\n")
		for _, item := range report.Errors {
			fmt.Fprintf(&output, "  %s [%s]: %s\n", reportLine(item.Target), reportLine(item.Code), reportLine(item.Message))
		}
	}
	output.WriteString("\nSource and observation context\n" + context + "\n")
	return []byte(output.String())
}

func renderNativeMarkdown(report Report, context string) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# Inspectyn security report\n\n**Status:** %s\n\nGenerated: %s | Inspectyn %s | %s\n\nTargets: %d | Findings: %d | Errors: %d\n\n%s\n\n## Targets\n\n", reportStatus(report), reportMarkdown(report.GeneratedAt), reportMarkdown(report.Tool.Version), report.Kind, len(report.Targets), len(report.Findings), len(report.Errors), reportCoverage)
	for _, target := range report.Targets {
		fmt.Fprintf(&output, "- %s\n", reportMarkdown(target))
	}
	output.WriteString("\n## Findings\n\n")
	if len(report.Findings) == 0 {
		output.WriteString("No findings were produced for this coverage.\n")
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&output, "### %s\n\n**Severity:** %s | **State:** %s\n\n**Target:** %s | **Rule:** %s\n\n**Evidence:** %s\n\n**Remediation:** %s\n\n", reportMarkdown(finding.Title), finding.Severity, reportMarkdown(displayFindingState(finding.State)), reportMarkdown(finding.Target), reportMarkdown(finding.RuleID), reportMarkdown(finding.Evidence), reportMarkdown(finding.Remediation))
	}
	if len(report.Errors) > 0 {
		output.WriteString("\n## Errors\n\n")
		for _, item := range report.Errors {
			fmt.Fprintf(&output, "- **%s** (%s): %s\n", reportMarkdown(item.Target), reportMarkdown(item.Code), reportMarkdown(item.Message))
		}
	}
	// An input containing backticks cannot terminate its own evidence fence.
	longest, run := 0, 0
	for _, ch := range context {
		if ch == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	fmt.Fprintf(&output, "\n## Source and observation context\n\n%sjson\n%s\n%s\n", fence, context, fence)
	return []byte(output.String())
}

const nativeHTMLReport = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Inspectyn security report</title><style>body{font:16px/1.6 system-ui,sans-serif;color:#172638;background:#f4f6f8;margin:0}main{max-width:960px;margin:40px auto;padding:32px;background:white;border:1px solid #d7dee7}h1,h2,h3{line-height:1.25}h2{margin-top:32px}.status{font-weight:700;padding:14px;background:#eef4f7;border-left:4px solid #376785}.coverage,pre{padding:16px;background:#f4f6f8}article{border-top:1px solid #d7dee7;padding:16px 0}dt{font-weight:600}dd{margin:0 0 14px}dd,pre,li{white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:640px){main{margin:0;padding:20px;border:0}}@media print{main{margin:0;border:0;padding:0}article{break-inside:avoid}}</style></head>
<body><main><h1>Inspectyn security report</h1><p class="status">{{.Status}}</p><p>{{.Report.GeneratedAt}} | Inspectyn {{clean .Report.Tool.Version}} | {{.Report.Kind}}</p><p>Targets: {{len .Report.Targets}} | Findings: {{len .Report.Findings}} | Errors: {{len .Report.Errors}}</p><p class="coverage">{{.Coverage}}</p><h2>Targets</h2><ul>{{range .Report.Targets}}<li>{{clean .}}</li>{{end}}</ul><h2>Findings</h2>{{range .Report.Findings}}<article><h3>{{clean .Title}}</h3><p>{{.Severity}} | {{state .State}}</p><dl><dt>Target / rule</dt><dd>{{clean .Target}} / {{clean .RuleID}}</dd><dt>Evidence</dt><dd>{{clean .Evidence}}</dd><dt>Remediation</dt><dd>{{clean .Remediation}}</dd></dl></article>{{else}}<p>No findings were produced for this coverage.</p>{{end}}{{if .Report.Errors}}<h2>Errors</h2><ul>{{range .Report.Errors}}<li><strong>{{clean .Target}}</strong> ({{clean .Code}}): {{clean .Message}}</li>{{end}}</ul>{{end}}<h2>Source and observation context</h2><pre>{{.Context}}</pre></main></body></html>
`

// RenderReport returns a self-contained report. JSON retains original evidence;
// human-readable output removes terminal controls and escapes untrusted content.
func RenderReport(report Report, format string) ([]byte, error) {
	if err := validateNativeReport(report); err != nil {
		return nil, err
	}
	if format == "" {
		format = "text"
	}
	if report.Targets == nil {
		report.Targets = []string{}
	}
	if report.Findings == nil {
		report.Findings = []Finding{}
	}
	if report.Errors == nil {
		report.Errors = []CheckError{}
	}
	if report.Observations == nil {
		report.Observations = []Observation{}
	}
	if report.Context == nil {
		report.Context = map[string]any{}
	}
	if format == "json" {
		status := "complete"
		if reportIncomplete(report) {
			status = "incomplete"
		}
		output, err := json.MarshalIndent(struct {
			Report
			Coverage map[string]string `json:"coverage"`
		}{report, map[string]string{"status": status, "statement": reportCoverage}}, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(output, '\n'), nil
	}
	context, err := reportContextJSON(report)
	if err != nil {
		return nil, err
	}
	switch format {
	case "text":
		return renderNativeText(report, context), nil
	case "markdown":
		return renderNativeMarkdown(report, context), nil
	case "html":
		tmpl, err := template.New("report").Funcs(template.FuncMap{"clean": cleanReportText, "state": displayFindingState}).Parse(nativeHTMLReport)
		if err != nil {
			return nil, err
		}
		var output bytes.Buffer
		err = tmpl.Execute(&output, struct {
			Report                    Report
			Status, Coverage, Context string
		}{report, reportStatus(report), reportCoverage, context})
		if err != nil {
			return nil, err
		}
		return output.Bytes(), nil
	default:
		return nil, fmt.Errorf("report format must be text, json, markdown or html")
	}
}
