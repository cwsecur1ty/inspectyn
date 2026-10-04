package inspect

import (
	"fmt"
	"strings"
	"time"
)

// evaluateWebMetadata intentionally runs regardless of document content type or
// HTTP success status. Cookies can also be set on redirects and error responses.
func evaluateWebMetadata(ob Observation, now time.Time, add findingAdder) {
	if ob.HTTP != nil && ob.HTTP.Cookies != nil {
		evaluateCookieMetadata(ob.HTTP.Cookies, add)
	}
	if ob.SecurityTXT != nil {
		evaluateSecurityTXT(ob.SecurityTXT, now, add)
	}
}

func evaluateCookieMetadata(ob *CookieObservation, add findingAdder) {
	if ob.Status != "ok" || ob.Invalid != 0 || ob.Total != len(ob.Items) || len(ob.Items) > maxObservedCookies {
		add("INSPECTYN_COOKIE_UNASSESSED", "info", "Some cookie attributes could not be assessed", "At least one Set-Cookie field was rejected, ambiguous, outside the observation limits, or not successfully collected. Findings cover only retained metadata.", "Review the response's Set-Cookie fields and repeat the check. Values and raw headers are deliberately excluded from reports.", "Not assessable")
	}
	missingSecure, missingHTTPOnly, unspecifiedSameSite, noneWithoutSecure, prefixViolation := 0, 0, 0, 0, 0
	invalidMetadata := false
	for _, cookie := range ob.Items {
		if cookie.Name == "" || len(cookie.Name) > maxObservedCookieName || !checkToken.MatchString(cookie.Name) {
			invalidMetadata = true
			continue
		}
		switch cookie.SameSite {
		case "unspecified", "lax", "strict", "none":
		default:
			invalidMetadata = true
			continue
		}
		if !cookie.Secure {
			missingSecure++
		}
		if !cookie.HTTPOnly {
			missingHTTPOnly++
		}
		if cookie.SameSite == "unspecified" {
			unspecifiedSameSite++
		}
		if cookie.SameSite == "none" && !cookie.Secure {
			noneWithoutSecure++
		}
		name := strings.ToLower(cookie.Name)
		if (strings.HasPrefix(name, "__secure-") && !cookie.Secure) || (strings.HasPrefix(name, "__host-") && (!cookie.Secure || cookie.DomainScoped || !cookie.PathRoot)) {
			prefixViolation++
		}
	}
	if invalidMetadata && ob.Status == "ok" && ob.Invalid == 0 && ob.Total == len(ob.Items) && len(ob.Items) <= maxObservedCookies {
		add("INSPECTYN_COOKIE_UNASSESSED", "info", "Some cookie attributes could not be assessed", "The retained cookie metadata contains an unsupported or invalid attribute representation.", "Collect a fresh observation before assessing the affected cookies.", "Not assessable")
	}
	if missingSecure > 0 {
		add("INSPECTYN_COOKIE_SECURE_MISSING", "low", "Cookies without Secure observed", fmt.Sprintf("%d observed cookie field(s) omit Secure. Cookie purpose, sensitivity, deletion intent, and browser storage were not assessed.", missingSecure), "Review cookie purpose and set Secure on cookies that should be transmitted only over HTTPS.", "Needs review")
	}
	if missingHTTPOnly > 0 {
		add("INSPECTYN_COOKIE_HTTPONLY_MISSING", "info", "Cookies without HttpOnly observed", fmt.Sprintf("%d observed cookie field(s) omit HttpOnly. Some application cookies intentionally require JavaScript access.", missingHTTPOnly), "Apply HttpOnly to sensitive cookies that do not need script access; confirm the application requirement before changing others.", "Needs review")
	}
	if unspecifiedSameSite > 0 {
		add("INSPECTYN_COOKIE_SAMESITE_UNSPECIFIED", "info", "Cookies without an explicit SameSite policy observed", fmt.Sprintf("%d observed cookie field(s) omit SameSite. Browser defaults apply; this alone does not demonstrate a cross-site request vulnerability.", unspecifiedSameSite), "Document the intended cross-site behavior and choose an explicit policy where appropriate for application flows.", "Observed")
	}
	if noneWithoutSecure > 0 {
		add("INSPECTYN_COOKIE_SAMESITE_NONE_INSECURE", "low", "SameSite=None cookies omit Secure", fmt.Sprintf("%d observed cookie field(s) combine SameSite=None with no Secure attribute. Browsers enforcing this requirement reject those cookies.", noneWithoutSecure), "Use Secure with SameSite=None and confirm that cross-site cookie behavior is required.", "Needs review")
	}
	if prefixViolation > 0 {
		add("INSPECTYN_COOKIE_PREFIX_INVALID", "low", "Cookie prefix requirements are not satisfied", fmt.Sprintf("%d observed cookie field(s) violate __Secure- or __Host- attribute requirements. Supporting browsers reject these configurations; exploitation was not demonstrated.", prefixViolation), "For __Secure- use Secure. For __Host- also omit Domain and explicitly set Path=/.", "Needs review")
	}
}

func evaluateSecurityTXT(ob *SecurityTXTObservation, now time.Time, add findingAdder) {
	switch ob.Status {
	case "absent":
		add("INSPECTYN_SECURITY_TXT_ABSENT", "info", "No security.txt file observed at the well-known path", "The exact /.well-known/security.txt request returned HTTP 404 or 410. Other disclosure channels were not searched.", "Consider publishing a security.txt file to document the intended vulnerability reporting channel.", "Needs review")
	case "invalid":
		add("INSPECTYN_SECURITY_TXT_INVALID", "low", "security.txt format needs review", "The response did not satisfy the checked media type, UTF-8, field syntax, Contact, or Expires requirements. This is a limited format assessment.", "Serve UTF-8 text/plain with at least one Contact URI and exactly one valid Expires timestamp; review the safe issue codes in the observation.", "Needs review")
	case "present":
		expires, err := time.Parse(time.RFC3339Nano, ob.Expires)
		if err != nil || ob.ContactCount < 1 || ob.Signed || (ob.CanonicalPresent && !ob.CanonicalMatches) {
			addSecurityTXTUnassessed(add)
			return
		}
		for _, issue := range ob.Issues {
			if issue != "EXPIRED" {
				addSecurityTXTUnassessed(add)
				return
			}
		}
		if !expires.After(now) {
			add("INSPECTYN_SECURITY_TXT_EXPIRED", "low", "security.txt has expired", "The observed Expires timestamp is at or before the assessment time. Contact reachability and ownership were not verified.", "Review the disclosure details and publish a current Expires timestamp after confirming they remain accurate.", "Needs review")
		}
	default:
		addSecurityTXTUnassessed(add)
	}
}

func addSecurityTXTUnassessed(add findingAdder) {
	add("INSPECTYN_SECURITY_TXT_UNASSESSED", "info", "security.txt could not be assessed", "The optional request was incomplete, redirected, unsupported, signed without signature verification, or did not establish a matching Canonical location. No healthy-file conclusion was made.", "Review the observation's safe issue codes. Verify any redirect, canonical location, or OpenPGP signature manually before relying on the file.", "Not assessable")
}
