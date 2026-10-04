package inspect

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Rule identifiers remain stable across the JavaScript and native editions.
// These checks inspect observations, not exploitability, CSP strength, or mail
// authentication. SPF includes and DMARC inheritance are not evaluated.
var (
	checkToken         = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	checkQuoted        = regexp.MustCompile(`^"(?:[^"\\\x00-\x1f\x7f]|\\[\x20-\x7e])*"$`)
	checkControls      = regexp.MustCompile(`[\x00-\x08\x0a-\x1f\x7f]`)
	checkDigits        = regexp.MustCompile(`^[0-9]+$`)
	checkMediaType     = regexp.MustCompile("(?i)^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+(?:\\s*;|$)")
	checkHTML          = regexp.MustCompile(`(?i)^(?:text/html|application/xhtml\+xml)(?:\s*;|$)`)
	checkAncestor      = regexp.MustCompile(`(?i)^frame-ancestors(?:\s|$)`)
	checkSPF           = regexp.MustCompile(`(?i)^v=spf1(?:\s|$)`)
	checkSPFAll        = regexp.MustCompile(`(?i)^[+?~-]?all$`)
	checkSPFInvalidAll = regexp.MustCompile(`(?i)^[+?~-]?all[:/=]`)
	checkDMARC         = regexp.MustCompile(`(?i)^v\s*=\s*DMARC1(?:\s*;|\s*$)`)
	checkDMARCTag      = regexp.MustCompile(`(?i)^([a-z]+)\s*=\s*(.+)$`)
	checkHostname      = regexp.MustCompile(`^[a-zA-Z0-9.\[\]:-]+$`)
)

type findingAdder func(ruleID, severity, title, evidence, remediation, state string)

func observationTarget(ob Observation) string {
	u, err := url.Parse(ob.URL)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" {
		// Keep endpoint identity without exporting URL credentials or query tokens.
		u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
		u.ForceQuery = false
		if u.Path == "" {
			u.Path = "/"
		}
		return u.String()
	}
	if checkHostname.MatchString(ob.Hostname) {
		return ob.Hostname
	}
	return "unknown target"
}

func hstsPolicyState(value string) string {
	var parts []string
	var part strings.Builder
	quoted, escaped := false, false
	for _, ch := range value {
		if escaped {
			part.WriteRune(ch)
			escaped = false
			continue
		}
		if quoted && ch == '\\' {
			part.WriteRune(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			quoted = !quoted
		}
		if ch == ';' && !quoted {
			parts = append(parts, strings.TrimSpace(part.String()))
			part.Reset()
		} else {
			part.WriteRune(ch)
		}
	}
	if quoted || escaped || checkControls.MatchString(value) {
		return "invalid"
	}
	parts = append(parts, strings.TrimSpace(part.String()))
	seen, maxAge := map[string]bool{}, ""
	for _, directive := range parts {
		if directive == "" {
			continue
		}
		name, argument, hasArgument := strings.Cut(directive, "=")
		name, argument = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(argument)
		if !checkToken.MatchString(name) || seen[name] {
			return "invalid"
		}
		seen[name] = true
		if hasArgument && !checkToken.MatchString(argument) && !checkQuoted.MatchString(argument) {
			return "invalid"
		}
		if name == "includesubdomains" && hasArgument {
			return "invalid"
		}
		if name == "max-age" {
			if strings.HasPrefix(argument, `"`) {
				argument = argument[1 : len(argument)-1]
				var unquoted strings.Builder
				for i := 0; i < len(argument); i++ {
					if argument[i] == '\\' {
						i++
					}
					unquoted.WriteByte(argument[i])
				}
				argument = unquoted.String()
			}
			if !checkDigits.MatchString(argument) {
				return "invalid"
			}
			maxAge = argument
		}
	}
	if maxAge == "" {
		return "invalid"
	}
	if strings.Trim(maxAge, "0") == "" {
		return "disabled"
	}
	return "present"
}

func evaluateHTTP(ob Observation, add findingAdder) {
	if ob.HTTP == nil {
		return
	}
	// Collect case-insensitively while preserving separate fields. The native
	// collector lowercases names, but mixed-case imported maps are also safe.
	headers := make(map[string][]string)
	for name, values := range ob.HTTP.Headers {
		key := strings.ToLower(name)
		for _, value := range values {
			headers[key] = append(headers[key], strings.TrimSpace(value))
		}
	}
	header := func(name string) string { return strings.Join(headers[name], ", ") }
	status := ob.HTTP.Status
	if status >= 300 && status < 400 {
		add("SPECTYN_HTTP_REDIRECT", "info", "Redirect response observed", fmt.Sprintf("HTTP %d was returned. The redirect destination was not followed or assessed.", status), "Assess each intended destination explicitly; these findings describe only the original response.", "")
	} else if status >= 400 && status < 600 {
		add("SPECTYN_HTTP_ERROR_RESPONSE", "info", "HTTP error response observed", fmt.Sprintf("HTTP %d was returned. Response-header findings may describe an error or access-control page.", status), "Confirm the expected public response and review the relevant application route separately.", "")
	}
	if strings.HasPrefix(strings.ToLower(ob.URL), "https://") {
		value, state := header("strict-transport-security"), "missing"
		if len(headers["strict-transport-security"]) > 1 {
			state = "invalid"
		} else if value != "" {
			state = hstsPolicyState(value)
		}
		if state != "present" {
			title, evidence := "HSTS policy needs correction", "The response has repeated HSTS header fields or a missing, malformed or duplicated directive."
			if state == "missing" {
				title, evidence = "HSTS response header missing", "No Strict-Transport-Security header was observed on this HTTPS response. Cached or parent-domain policies were not assessed."
			}
			if state == "disabled" {
				title, evidence = "HSTS disabled by max-age=0", "The response includes an HSTS max-age of zero."
			}
			add("SPECTYN_HSTS_"+strings.ToUpper(state), "low", title, evidence, "Review the host's HTTPS policy and configure one valid HSTS policy with a positive max-age. Confirm subdomain readiness before expanding its scope.", "")
		}
	}
	if status < 200 || status >= 300 || status == 204 || status == 205 {
		return
	}
	contentType := header("content-type")
	unknown := len(headers["content-type"]) != 1 || contentType == "" || strings.Contains(contentType, ",") || !checkMediaType.MatchString(contentType)
	if unknown {
		evidence := "The successful response has a repeated or ambiguous Content-Type value. HTML-specific CSP and framing checks were not assessed."
		if contentType == "" {
			evidence = "The successful response has no Content-Type header. HTML-specific CSP and framing checks were not assessed."
		}
		add("SPECTYN_CONTENT_TYPE_UNASSESSED", "info", "Document response policy could not be assessed", evidence, "Serve one valid Content-Type for this endpoint, then reassess its document response policies.", "Not assessable")
	}
	nosniff := header("x-content-type-options")
	if len(headers["x-content-type-options"]) != 1 || !strings.EqualFold(nosniff, "nosniff") {
		evidence := "No X-Content-Type-Options header was observed on this response."
		if nosniff != "" {
			evidence = "X-Content-Type-Options is not a single recognized nosniff value."
		}
		add("SPECTYN_NOSNIFF_MISSING_OR_INVALID", "low", "Content-type protection needs review", evidence, "Set X-Content-Type-Options: nosniff and serve the intended Content-Type on relevant responses.", "")
	}
	if unknown || !checkHTML.MatchString(contentType) {
		return
	}
	csp := header("content-security-policy")
	if csp == "" {
		evidence := "No enforced Content-Security-Policy header was observed on this HTML response. Meta-element policies were not inspected."
		if header("content-security-policy-report-only") != "" {
			evidence = "Only a report-only CSP header was observed on this HTML response. Meta-element policies were not inspected."
		}
		add("SPECTYN_CSP_MISSING", "low", "Enforced CSP response header missing", evidence, "Develop and test an application-specific CSP, then enforce it after reviewing legitimate resource requirements.", "")
	}
	var ancestors []string
	for _, policy := range strings.Split(csp, ",") {
		for _, directive := range strings.Split(policy, ";") {
			directive = strings.TrimSpace(directive)
			if checkAncestor.MatchString(directive) {
				ancestors = append(ancestors, strings.TrimSpace(directive[len("frame-ancestors"):]))
				break
			}
		}
	}
	xfo := header("x-frame-options")
	validXFO := len(headers["x-frame-options"]) == 1 && (strings.EqualFold(xfo, "DENY") || strings.EqualFold(xfo, "SAMEORIGIN"))
	if len(ancestors) == 0 && !validXFO {
		add("SPECTYN_FRAMING_POLICY_MISSING", "low", "Framing response policy needs review", "This HTML response has neither an enforced CSP frame-ancestors directive nor a single recognized DENY or SAMEORIGIN X-Frame-Options value.", "Review legitimate embedding requirements and set CSP frame-ancestors for the approved parent origins.", "")
	} else if len(ancestors) > 0 {
		allBroad := true
		for _, policy := range ancestors {
			if policy != "*" {
				allBroad = false
			}
		}
		if allBroad {
			add("SPECTYN_FRAMING_POLICY_BROAD", "low", "Framing directive needs review", "The observed frame-ancestors directives allow all origins. An enforced CSP directive can take precedence over X-Frame-Options.", "Review the intended framing behavior and explicitly restrict ancestors where appropriate.", "")
		}
	}
}

func evaluateSPF(result DNSResult, add findingAdder) {
	if result.Status != "ok" && result.Status != "absent" {
		return
	}
	var records []string
	for _, record := range result.Records {
		if checkSPF.MatchString(record) {
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		add("SPECTYN_SPF_NOT_OBSERVED", "low", "SPF record not observed", "No SPF version 1 record was returned for the queried hostname. This does not determine its mail-sending role.", "Confirm which domains send mail and publish an appropriate SPF policy after inventorying legitimate senders.", "")
		return
	}
	if len(records) > 1 {
		add("SPECTYN_SPF_MULTIPLE", "medium", "Multiple SPF records observed", fmt.Sprintf("%d SPF version 1 records were returned at the same hostname. SPF requires a single policy record.", len(records)), "Consolidate the intended authorization policy into one SPF record and validate it with the mail operator.", "")
		return
	}
	terms := strings.Fields(records[0])
	redirects, all, invalid := 0, "", false
	for _, ch := range records[0] {
		if ch <= 0x1f || ch == 0x7f {
			invalid = true
		}
	}
	for _, term := range terms[1:] {
		if strings.HasPrefix(strings.ToLower(term), "redirect=") {
			redirects++
		}
		if checkSPFInvalidAll.MatchString(term) {
			invalid = true
		}
		if all == "" && checkSPFAll.MatchString(term) {
			all = strings.ToLower(term)
		}
	}
	if invalid || redirects > 1 {
		add("SPECTYN_SPF_INVALID", "medium", "SPF policy syntax needs review", "The observed SPF record has a control character, repeated redirect modifier or malformed all mechanism. Other SPF syntax and DNS dependencies were not evaluated.", "Validate the full SPF record, including included policies, using an SPF validator and the authoritative mail configuration.", "")
		return
	}
	switch {
	case all == "all" || all == "+all":
		add("SPECTYN_SPF_ALLOW_ALL", "high", "SPF has a permissive all mechanism", "The first all mechanism has a pass qualifier. Any sender reaching that mechanism receives an SPF pass; preceding mechanisms were not evaluated.", "Review legitimate senders and replace the permissive fallback with the mail owner's intended policy.", "")
	case all == "~all" || all == "?all":
		evidence := "The first all mechanism returns neutral. This does not establish how receivers handle mail or whether DMARC passes."
		if all == "~all" {
			evidence = "The first all mechanism requests softfail. This can be an intentional rollout policy and does not establish a DMARC failure."
		}
		add("SPECTYN_SPF_SOFT_POLICY", "low", "SPF fallback requests review", evidence, "Review the fallback against the authorized sender inventory before deciding whether a fail policy is appropriate.", "")
	case all == "" && redirects == 0:
		add("SPECTYN_SPF_IMPLICIT_NEUTRAL", "low", "SPF has an implicit neutral fallback", "No all mechanism or redirect modifier was observed. SPF falls back to neutral when no preceding mechanism matches.", "Confirm the intended fallback with the mail operator. The tool does not evaluate mechanisms or DNS lookup limits.", "")
	}
}

func evaluateDMARC(result DNSResult, add findingAdder) {
	if result.Status != "ok" && result.Status != "absent" {
		return
	}
	var records []string
	for _, record := range result.Records {
		if checkDMARC.MatchString(record) {
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		add("SPECTYN_DMARC_NOT_OBSERVED", "info", "Direct DMARC record not observed", "No DMARC record was observed at the queried _dmarc hostname. A parent-domain policy may apply; policy inheritance was not assessed.", "Determine the effective DMARC policy for the mail Author Domain, including inherited policy, before changing DNS.", "")
		return
	}
	if len(records) > 1 {
		add("SPECTYN_DMARC_MULTIPLE", "medium", "Multiple DMARC records observed", fmt.Sprintf("%d DMARC policy records were returned at the same hostname. Policy discovery cannot select a single local policy.", len(records)), "Consolidate the intended policy into one DMARC record and verify effective policy discovery.", "")
		return
	}
	tags, invalid := map[string]string{}, checkControls.MatchString(records[0])
	for _, part := range strings.Split(records[0], ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		match := checkDMARCTag.FindStringSubmatch(part)
		if match == nil {
			invalid = true
			continue
		}
		name := strings.ToLower(match[1])
		if _, exists := tags[name]; exists {
			invalid = true
		}
		tags[name] = strings.TrimSpace(match[2])
	}
	if tags["v"] != "DMARC1" {
		invalid = true
	}
	for _, name := range []string{"p", "sp", "np"} {
		if value, exists := tags[name]; exists && !strings.EqualFold(value, "none") && !strings.EqualFold(value, "quarantine") && !strings.EqualFold(value, "reject") {
			invalid = true
		}
	}
	if value, exists := tags["t"]; exists && !strings.EqualFold(value, "y") && !strings.EqualFold(value, "n") {
		invalid = true
	}
	if invalid {
		add("SPECTYN_DMARC_INVALID", "medium", "DMARC policy syntax needs review", "The local record has a malformed or repeated tag, invalid version, or unrecognized policy value. Receiver fallback behavior and the full record were not evaluated.", "Validate the DMARC record against RFC 9989 and verify effective policy with the mail operator.", "")
		return
	}
	if policy, exists := tags["p"]; !exists || strings.EqualFold(policy, "none") {
		evidence := "The local DMARC record specifies p=none; it does not request quarantine or rejection of failing mail."
		if !exists {
			evidence = "The local DMARC record omits p; RFC 9989 describes a default monitoring policy. Effective receiver behavior was not tested."
		}
		add("SPECTYN_DMARC_MONITORING", "low", "DMARC monitoring policy observed", evidence, "Review authentication reports and legitimate mail flows before deciding whether an enforcement policy is appropriate.", "")
	} else if strings.EqualFold(tags["t"], "y") {
		add("SPECTYN_DMARC_TEST_MODE", "low", "DMARC test mode observed", "The local DMARC record enables t=y. Under RFC 9989, receivers apply a policy one level below the declared enforcement policy.", "Confirm whether test mode is intentional and complete mail-flow review before moving to full enforcement.", "")
	}
}

// EvaluateObservation makes no network requests and does not mutate the input.
// Missing or skipped phases are not evaluated; failed phases remain unresolved.
func EvaluateObservation(ob Observation, now time.Time) []Finding {
	findings := []Finding{}
	target := observationTarget(ob)
	add := func(ruleID, severity, title, evidence, remediation, state string) {
		findings = append(findings, Finding{RuleID: ruleID, Severity: severity, Title: title, Evidence: evidence, Remediation: remediation, Target: target, State: state})
	}
	evaluateHTTP(ob, add)
	evaluateWebMetadata(ob, now, add)
	if ob.TLS != nil {
		if !ob.TLS.Authorized {
			add("SPECTYN_TLS_INVALID", "high", "TLS certificate verification failed", "The TLS observation does not confirm successful certificate and hostname verification.", "Verify the certificate hostname, validity and chain before relying on the other TLS observations.", "Not assessable")
		}
		expiry, err := time.Parse(time.RFC3339Nano, ob.TLS.ValidTo)
		if err != nil {
			add("SPECTYN_TLS_EXPIRY_UNKNOWN", "info", "Certificate expiry could not be assessed", "The TLS observation did not include a valid certificate expiry timestamp.", "Inspect the served certificate and its renewal configuration.", "Not assessable")
		} else {
			remaining := expiry.Sub(now)
			if remaining <= 30*24*time.Hour {
				ruleID, severity, title := "SPECTYN_TLS_EXPIRING", "medium", "Certificate renewal window is approaching"
				if remaining <= 7*24*time.Hour {
					severity = "high"
				}
				if remaining <= 0 {
					ruleID, title = "SPECTYN_TLS_EXPIRED", "Certificate expiry has passed"
				}
				evidence := "The observed certificate expires at " + expiry.UTC().Format(time.RFC3339Nano)
				if remaining > 0 {
					evidence += fmt.Sprintf(" (within %d days)", int(math.Ceil(remaining.Hours()/24)))
				}
				add(ruleID, severity, title, evidence+".", "Verify automated renewal and deployment of the replacement certificate before the expiry deadline.", "")
			}
		}
	}
	if ob.DNS != nil {
		var incomplete []string
		for _, query := range []struct {
			name   string
			result DNSResult
		}{{"A", ob.DNS.A}, {"AAAA", ob.DNS.AAAA}, {"SPF", ob.DNS.SPF}, {"DMARC", ob.DNS.DMARC}, {"MX", ob.DNS.MX}} {
			if query.result.Status == "error" {
				incomplete = append(incomplete, query.name)
			}
		}
		for _, query := range []struct {
			name   string
			result *DNSResult
		}{{"NS", ob.DNS.NS}, {"canonical name", ob.DNS.CNAME}} {
			if query.result != nil && query.result.Status == "error" {
				incomplete = append(incomplete, query.name)
			}
		}
		if len(incomplete) > 0 {
			add("SPECTYN_DNS_CHECK_INCOMPLETE", "info", "DNS checks incomplete", "The following lookups failed: "+strings.Join(incomplete, ", ")+". Missing-record conclusions were not made for those lookups.", "Retry the failed lookups and check resolver availability before drawing conclusions about DNS policy.", "Not assessable")
		}
		evaluateSPF(ob.DNS.SPF, add)
		evaluateDMARC(ob.DNS.DMARC, add)
	}
	return findings
}
