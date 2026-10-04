package inspect

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func webMetadataFindings(ob Observation) []Finding {
	findings := []Finding{}
	evaluateWebMetadata(ob, securityTXTTestNow, func(ruleID, severity, title, evidence, remediation, state string) {
		findings = append(findings, Finding{RuleID: ruleID, Severity: severity, Title: title, Evidence: evidence, Remediation: remediation, State: state, Target: observationTarget(ob)})
	})
	return findings
}

func webFinding(findings []Finding, ruleID string) *Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestCookieFindingsConservativeAcrossResponseStatus(t *testing.T) {
	for _, status := range []int{200, 302, 404, 500} {
		ob := Observation{URL: "https://example.com/", HTTP: &HTTPObservation{Status: status, Cookies: CaptureCookies(http.Header{"Set-Cookie": {"ordinary=SECRET"}})}}
		findings := webMetadataFindings(ob)
		for _, tc := range []struct{ rule, severity, state string }{
			{"INSPECTYN_COOKIE_SECURE_MISSING", "low", "Needs review"},
			{"INSPECTYN_COOKIE_HTTPONLY_MISSING", "info", "Needs review"},
			{"INSPECTYN_COOKIE_SAMESITE_UNSPECIFIED", "info", "Observed"},
		} {
			finding := webFinding(findings, tc.rule)
			if finding == nil || finding.Severity != tc.severity || finding.State != tc.state {
				t.Fatalf("HTTP %d: expected %s/%s/%s, got %#v", status, tc.rule, tc.severity, tc.state, findings)
			}
		}
		encoded, _ := json.Marshal(findings)
		if strings.Contains(string(encoded), "SECRET") {
			t.Fatal("cookie value leaked to findings")
		}
	}
}

func TestCookieConfigurationRejectedIsReviewNotExploit(t *testing.T) {
	ob := Observation{HTTP: &HTTPObservation{Cookies: CaptureCookies(http.Header{"Set-Cookie": {
		"__secure-session=secret; SameSite=None",
		"__HOST-session=secret; Secure; Domain=example.com; Path=/",
		"__Host-other=secret; Secure; Path=/nested",
	}})}}
	findings := webMetadataFindings(ob)
	for _, rule := range []string{"INSPECTYN_COOKIE_PREFIX_INVALID", "INSPECTYN_COOKIE_SAMESITE_NONE_INSECURE"} {
		finding := webFinding(findings, rule)
		if finding == nil || finding.Severity != "low" || finding.State != "Needs review" || !strings.Contains(finding.Evidence, "reject") {
			t.Fatalf("configuration semantics missing for %s: %#v", rule, findings)
		}
	}
	if finding := webFinding(findings, "INSPECTYN_COOKIE_PREFIX_INVALID"); !strings.Contains(finding.Evidence, "3 observed") {
		t.Fatal("prefix findings should aggregate per target, including case variants")
	}
	clean := Observation{HTTP: &HTTPObservation{Cookies: CaptureCookies(http.Header{"Set-Cookie": {"__Host-good=secret; Secure; HttpOnly; Path=/; SameSite=None"}})}}
	if findings := webMetadataFindings(clean); len(findings) != 0 {
		t.Fatalf("intentional SameSite=None incorrectly flagged: %#v", findings)
	}
}

func TestWebMetadataMissingIsNotInventedAndFailureNeverClean(t *testing.T) {
	for _, ob := range []Observation{{}, {HTTP: &HTTPObservation{Status: 200}}, {DNS: &DNSObservation{}}} {
		if findings := webMetadataFindings(ob); len(findings) != 0 {
			t.Fatalf("invented missing optional checks: %#v", findings)
		}
	}
	for _, ob := range []Observation{
		{HTTP: &HTTPObservation{Cookies: CaptureCookies(http.Header{"Set-Cookie": {"bad field"}})}},
		{HTTP: &HTTPObservation{Cookies: &CookieObservation{Status: "ok", Total: 1, Items: []CookieAttributes{{Name: "cookie", SameSite: "unexpected"}}}}},
		{HTTP: &HTTPObservation{Cookies: &CookieObservation{Status: "unknown", Items: []CookieAttributes{}}}},
		{SecurityTXT: &SecurityTXTObservation{Status: "error"}},
		{SecurityTXT: &SecurityTXTObservation{Status: "redirect"}},
		{SecurityTXT: &SecurityTXTObservation{Status: "unassessed", Signed: true}},
		{SecurityTXT: &SecurityTXTObservation{Status: "present"}},
		{SecurityTXT: &SecurityTXTObservation{Status: "future-status"}},
	} {
		findings := webMetadataFindings(ob)
		if len(findings) == 0 || findings[0].State != "Not assessable" {
			t.Fatalf("incomplete observation lacks unresolved finding: %#v", findings)
		}
		report := sampleReport()
		report.Findings, report.Errors = findings, []CheckError{}
		assertReportCode(t, report, "none", 2)
		assertReportCode(t, report, "critical", 2)
	}
}

func TestSecurityTXTFindingsKeepAbsenceSeparateFromFailure(t *testing.T) {
	for _, tc := range []struct{ status, rule, severity, state string }{
		{"absent", "INSPECTYN_SECURITY_TXT_ABSENT", "info", "Needs review"},
		{"invalid", "INSPECTYN_SECURITY_TXT_INVALID", "low", "Needs review"},
		{"redirect", "INSPECTYN_SECURITY_TXT_UNASSESSED", "info", "Not assessable"},
		{"unassessed", "INSPECTYN_SECURITY_TXT_UNASSESSED", "info", "Not assessable"},
		{"error", "INSPECTYN_SECURITY_TXT_UNASSESSED", "info", "Not assessable"},
	} {
		findings := webMetadataFindings(Observation{SecurityTXT: &SecurityTXTObservation{Status: tc.status}})
		finding := webFinding(findings, tc.rule)
		if finding == nil || finding.Severity != tc.severity || finding.State != tc.state {
			t.Fatalf("status %s: %#v", tc.status, findings)
		}
	}
	for _, tc := range []struct {
		expires string
		expired bool
	}{{"2026-10-04T12:00:00Z", true}, {"2026-10-04T12:00:01Z", false}} {
		ob := parseSecurityTXTTest("Contact: mailto:security@example.com\nExpires: " + tc.expires + "\n")
		findings := webMetadataFindings(Observation{SecurityTXT: ob})
		if (webFinding(findings, "INSPECTYN_SECURITY_TXT_EXPIRED") != nil) != tc.expired {
			t.Fatalf("expiry boundary %s: %#v", tc.expires, findings)
		}
	}
}
