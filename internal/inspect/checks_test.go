package inspect

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var checksNow = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

func checkFixtureObservation() Observation {
	return Observation{
		URL: "https://example.com/", Hostname: "example.com", ObservedAt: checksNow.Format(time.RFC3339),
		HTTP: &HTTPObservation{Status: 200, Headers: map[string][]string{
			"content-type": {"text/html; charset=utf-8"}, "strict-transport-security": {"max-age=31536000; includeSubDomains"},
			"x-content-type-options": {"nosniff"}, "content-security-policy": {"default-src 'self'; frame-ancestors 'none'"},
		}},
		TLS: &TLSObservation{Authorized: true, Protocol: "TLSv1.3", ValidTo: "2027-01-01T00:00:00Z"},
		DNS: &DNSObservation{SPF: DNSResult{Status: "ok", Records: []string{"v=spf1 -all"}}, DMARC: DNSResult{Status: "ok", Records: []string{"v=DMARC1; p=reject"}}, MX: DNSResult{Status: "ok", Records: []string{}}},
	}
}

func editedFindings(edit func(*Observation)) []Finding {
	ob := checkFixtureObservation()
	if edit != nil {
		edit(&ob)
	}
	return EvaluateObservation(ob, checksNow)
}

func checkIDs(findings []Finding) []string {
	ids := []string{}
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}

func assertCheckIDs(t *testing.T, findings []Finding, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := checkIDs(findings); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
}

func TestEvaluateHealthyAndPartialObservations(t *testing.T) {
	assertCheckIDs(t, editedFindings(nil))
	assertCheckIDs(t, EvaluateObservation(Observation{URL: "https://example.com/"}, checksNow))
	ob := checkFixtureObservation()
	before, _ := json.Marshal(ob)
	EvaluateObservation(ob, checksNow)
	after, _ := json.Marshal(ob)
	if string(before) != string(after) {
		t.Fatal("evaluation mutated input")
	}
}

func TestHSTSQuotedAndInvalidDirectives(t *testing.T) {
	for _, value := range []string{`max-age="31536000"`, `max-age="\1\0"`, `MAX-AGE=10; extension="x;y"`, "max-age=99999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			assertCheckIDs(t, editedFindings(func(ob *Observation) { ob.HTTP.Headers["strict-transport-security"] = []string{value} }))
		})
	}
	for _, value := range []string{"max-age=-1", "max-age=abc", "max-age=10; max-age=20", "max-age=10, max-age=20", "includeSubDomains", "max-age=10; includeSubDomains=true", `max-age="10`, `max-age="\"`, "max-age=10\n"} {
		// Surrounding whitespace is normalized like an HTTP field before parsing.
		if strings.HasSuffix(value, "\n") {
			continue
		}
		t.Run(value, func(t *testing.T) {
			assertCheckIDs(t, editedFindings(func(ob *Observation) { ob.HTTP.Headers["strict-transport-security"] = []string{value} }), "SPECTYN_HSTS_INVALID")
		})
	}
	assertCheckIDs(t, editedFindings(func(ob *Observation) { delete(ob.HTTP.Headers, "strict-transport-security") }), "SPECTYN_HSTS_MISSING")
	assertCheckIDs(t, editedFindings(func(ob *Observation) { ob.HTTP.Headers["strict-transport-security"] = []string{"max-age=000"} }), "SPECTYN_HSTS_DISABLED")
	assertCheckIDs(t, editedFindings(func(ob *Observation) {
		ob.URL = "http://example.com/"
		delete(ob.HTTP.Headers, "strict-transport-security")
	}))
}

func TestHTTPContextAndDuplicateFields(t *testing.T) {
	for _, contentType := range [][]string{nil, {""}, {"text/html", "application/json"}, {"text/html", "text/html"}, {"text/html, application/json"}} {
		findings := editedFindings(func(ob *Observation) {
			ob.HTTP.Headers["content-type"] = contentType
			delete(ob.HTTP.Headers, "content-security-policy")
		})
		assertCheckIDs(t, findings, "SPECTYN_CONTENT_TYPE_UNASSESSED")
		if findings[0].State != "Not assessable" {
			t.Fatal("ambiguous response context must stay unresolved")
		}
	}
	for _, item := range []struct {
		name   string
		values []string
		rule   string
	}{
		{"strict-transport-security", []string{"max-age=10", "max-age=10"}, "SPECTYN_HSTS_INVALID"},
		{"x-content-type-options", []string{"nosniff", "nosniff"}, "SPECTYN_NOSNIFF_MISSING_OR_INVALID"},
		{"x-frame-options", []string{"DENY", "DENY"}, "SPECTYN_FRAMING_POLICY_MISSING"},
	} {
		findings := editedFindings(func(ob *Observation) {
			ob.HTTP.Headers[item.name] = item.values
			if item.name == "x-frame-options" {
				ob.HTTP.Headers["content-security-policy"] = []string{"default-src 'self'"}
			}
		})
		assertCheckIDs(t, findings, item.rule)
	}
	for _, contentType := range []string{"application/json", "image/png", "text/html-incorrect"} {
		assertCheckIDs(t, editedFindings(func(ob *Observation) {
			ob.HTTP.Headers["content-type"] = []string{contentType}
			delete(ob.HTTP.Headers, "content-security-policy")
		}))
	}
	assertCheckIDs(t, editedFindings(func(ob *Observation) {
		ob.HTTP.Headers["content-type"] = []string{"application/json"}
		delete(ob.HTTP.Headers, "x-content-type-options")
	}), "SPECTYN_NOSNIFF_MISSING_OR_INVALID")
	assertCheckIDs(t, editedFindings(func(ob *Observation) {
		delete(ob.HTTP.Headers, "content-type")
		ob.HTTP.Headers["Content-Type"] = []string{"text/html"}
	}))
}

func TestCSPAndFramingPolicies(t *testing.T) {
	findings := editedFindings(func(ob *Observation) {
		delete(ob.HTTP.Headers, "content-security-policy")
		ob.HTTP.Headers["content-security-policy-report-only"] = []string{"frame-ancestors 'none'"}
	})
	assertCheckIDs(t, findings, "SPECTYN_CSP_MISSING", "SPECTYN_FRAMING_POLICY_MISSING")
	if !strings.Contains(findings[0].Evidence, "report-only") {
		t.Fatal("report-only policy must not imply enforcement")
	}
	for _, xfo := range []string{"DENY", "sameorigin"} {
		assertCheckIDs(t, editedFindings(func(ob *Observation) {
			ob.HTTP.Headers["content-security-policy"] = []string{"default-src 'self'"}
			ob.HTTP.Headers["x-frame-options"] = []string{xfo}
		}))
	}
	for _, csp := range [][]string{{"frame-ancestors *"}, {"frame-ancestors *; frame-ancestors 'none'"}} {
		assertCheckIDs(t, editedFindings(func(ob *Observation) {
			ob.HTTP.Headers["content-security-policy"] = csp
			ob.HTTP.Headers["x-frame-options"] = []string{"DENY"}
		}), "SPECTYN_FRAMING_POLICY_BROAD")
	}
	for _, csp := range [][]string{{"frame-ancestors *, frame-ancestors 'none'"}, {"frame-ancestors *", "frame-ancestors 'none'"}, {"frame-ancestors"}, {"frame-ancestors *, frame-ancestors"}} {
		assertCheckIDs(t, editedFindings(func(ob *Observation) { ob.HTTP.Headers["content-security-policy"] = csp }))
	}
}

func TestHTTPNonDocumentResponses(t *testing.T) {
	for _, status := range []int{301, 302, 307, 404, 500, 204, 205} {
		findings := editedFindings(func(ob *Observation) {
			ob.HTTP.Status = status
			ob.HTTP.Headers = map[string][]string{"strict-transport-security": {"max-age=10"}}
		})
		if status < 300 {
			assertCheckIDs(t, findings)
		} else if status < 400 {
			assertCheckIDs(t, findings, "SPECTYN_HTTP_REDIRECT")
		} else {
			assertCheckIDs(t, findings, "SPECTYN_HTTP_ERROR_RESPONSE")
		}
	}
}

func TestTLSExpiryExactBoundariesAndUnknowns(t *testing.T) {
	for _, item := range []struct {
		remaining time.Duration
		severity  string
		rule      string
	}{
		{30*24*time.Hour + time.Second, "", ""}, {30 * 24 * time.Hour, "medium", "SPECTYN_TLS_EXPIRING"},
		{7*24*time.Hour + time.Second, "medium", "SPECTYN_TLS_EXPIRING"}, {7 * 24 * time.Hour, "high", "SPECTYN_TLS_EXPIRING"},
		{time.Second, "high", "SPECTYN_TLS_EXPIRING"}, {0, "high", "SPECTYN_TLS_EXPIRED"}, {-time.Hour, "high", "SPECTYN_TLS_EXPIRED"},
	} {
		findings := editedFindings(func(ob *Observation) { ob.TLS.ValidTo = checksNow.Add(item.remaining).Format(time.RFC3339Nano) })
		if item.rule == "" {
			assertCheckIDs(t, findings)
			continue
		}
		assertCheckIDs(t, findings, item.rule)
		if findings[0].Severity != item.severity {
			t.Fatalf("duration %v: severity = %s", item.remaining, findings[0].Severity)
		}
	}
	for _, value := range []string{"", "bad timestamp"} {
		findings := editedFindings(func(ob *Observation) { ob.TLS.ValidTo = value })
		assertCheckIDs(t, findings, "SPECTYN_TLS_EXPIRY_UNKNOWN")
		if findings[0].State != "Not assessable" {
			t.Fatal("unknown expiry must be unresolved")
		}
	}
	findings := editedFindings(func(ob *Observation) { ob.TLS.Authorized = false })
	assertCheckIDs(t, findings, "SPECTYN_TLS_INVALID")
	if findings[0].State != "Not assessable" {
		t.Fatal("unverified TLS must be unresolved")
	}
}

func TestDNSFailuresSkippedAndAbsent(t *testing.T) {
	for _, status := range []string{"", "skipped"} {
		ob := Observation{Hostname: "example.com", DNS: &DNSObservation{SPF: DNSResult{Status: status}, DMARC: DNSResult{Status: status}}}
		assertCheckIDs(t, EvaluateObservation(ob, checksNow))
	}
	ob := Observation{Hostname: "example.com", DNS: &DNSObservation{A: DNSResult{Status: "error", Error: "SECRET_DNS"}, SPF: DNSResult{Status: "error", Error: "SECRET_DNS"}, DMARC: DNSResult{Status: "error"}}}
	findings := EvaluateObservation(ob, checksNow)
	assertCheckIDs(t, findings, "SPECTYN_DNS_CHECK_INCOMPLETE")
	if findings[0].State != "Not assessable" || !strings.Contains(findings[0].Evidence, "A, SPF, DMARC") {
		t.Fatal("failed DNS must be explicitly unresolved")
	}
	data, _ := json.Marshal(findings)
	if strings.Contains(string(data), "SECRET") {
		t.Fatal("resolver details leaked into findings")
	}
	ob.DNS = &DNSObservation{SPF: DNSResult{Status: "absent"}, DMARC: DNSResult{Status: "absent"}}
	findings = EvaluateObservation(ob, checksNow)
	assertCheckIDs(t, findings, "SPECTYN_SPF_NOT_OBSERVED", "SPECTYN_DMARC_NOT_OBSERVED")
	if findings[1].Severity != "info" || !strings.Contains(findings[1].Evidence, "parent-domain policy may apply") {
		t.Fatal("DMARC absence overstates coverage")
	}
}

func dnsFindings(kind string, records ...string) []Finding {
	dns := &DNSObservation{}
	if kind == "spf" {
		dns.SPF = DNSResult{Status: "ok", Records: records}
	} else {
		dns.DMARC = DNSResult{Status: "ok", Records: records}
	}
	return EvaluateObservation(Observation{Hostname: "example.com", DNS: dns}, checksNow)
}

func TestSPFPolicyOrdering(t *testing.T) {
	assertCheckIDs(t, dnsFindings("spf", "v=spf1 -all", "v=spf1 ~all"), "SPECTYN_SPF_MULTIPLE")
	for _, policy := range []string{"v=spf1 all", "v=spf1 +all", "v=spf1 include:example.org +all"} {
		findings := dnsFindings("spf", policy)
		assertCheckIDs(t, findings, "SPECTYN_SPF_ALLOW_ALL")
		if findings[0].Severity != "high" {
			t.Fatal("allow-all should be high")
		}
	}
	for _, policy := range []string{"v=spf1 -all +all", "v=spf1 redirect=example.org"} {
		assertCheckIDs(t, dnsFindings("spf", policy))
	}
	for _, policy := range []string{"v=spf1 ~all", "v=spf1 ?all"} {
		assertCheckIDs(t, dnsFindings("spf", policy), "SPECTYN_SPF_SOFT_POLICY")
	}
	assertCheckIDs(t, dnsFindings("spf", "v=spf1 mx"), "SPECTYN_SPF_IMPLICIT_NEUTRAL")
	for _, policy := range []string{"v=spf1 redirect=a.example redirect=b.example", "v=spf1 all:anything", "v=spf1\n-all"} {
		assertCheckIDs(t, dnsFindings("spf", policy), "SPECTYN_SPF_INVALID")
	}
	assertCheckIDs(t, dnsFindings("spf", "unrelated-verification=record", "v=spf1 -all"))
}

func TestDMARCMonitoringAmbiguityAndCurrentTestMode(t *testing.T) {
	assertCheckIDs(t, dnsFindings("dmarc", "v=DMARC1; p=reject", "v=DMARC1; p=none"), "SPECTYN_DMARC_MULTIPLE")
	for _, policy := range []string{"v=DMARC1; p=nonsense", "v=dmarc1; p=reject", "v=DMARC1; p=reject; p=none", "v=DMARC1; sp=bad", "v=DMARC1; t=maybe"} {
		assertCheckIDs(t, dnsFindings("dmarc", policy), "SPECTYN_DMARC_INVALID")
	}
	for _, policy := range []string{"v=DMARC1", "v = DMARC1; p=none"} {
		assertCheckIDs(t, dnsFindings("dmarc", policy), "SPECTYN_DMARC_MONITORING")
	}
	assertCheckIDs(t, dnsFindings("dmarc", "v=DMARC1; p=reject; t=y"), "SPECTYN_DMARC_TEST_MODE")
	for _, policy := range []string{"v=DMARC1; p=quarantine", "v=DMARC1;\tp=reject", "v=DMARC1; p=reject; pct=0", "v=DMARC1; p=reject; t=n; np=reject"} {
		assertCheckIDs(t, dnsFindings("dmarc", policy))
	}
}

func TestFindingsKeepEndpointAndOmitSensitiveRawMaterial(t *testing.T) {
	findings := editedFindings(func(ob *Observation) {
		ob.URL = "https://user:SECRET_PASSWORD@example.com/intended-path?token=SECRET_QUERY#SECRET_FRAGMENT"
		ob.HTTP.Headers = map[string][]string{"content-type": {"text/html"}, "set-cookie": {"SECRET_COOKIE"}, "authorization": {"SECRET_AUTH"}, "strict-transport-security": {"SECRET_HSTS"}}
		ob.DNS.SPF.Records = []string{"v=spf1 include:SECRET_DOMAIN +all"}
		ob.DNS.DMARC.Records = []string{"v=DMARC1; p=none; rua=mailto:SECRET_MAILBOX@example.com"}
	})
	data, _ := json.Marshal(findings)
	if strings.Contains(string(data), "SECRET_") {
		t.Fatal("raw input leaked into findings")
	}
	for _, finding := range findings {
		if finding.Target != "https://example.com/intended-path" {
			t.Fatalf("unexpected target %q", finding.Target)
		}
	}
}
