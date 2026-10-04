package inspect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const securityTXTTestURL = "https://example.com/.well-known/security.txt"

var securityTXTTestNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func parseSecurityTXTTest(body string) *SecurityTXTObservation {
	return ParseSecurityTXT(securityTXTTestURL, 200, "text/plain; charset=utf-8", []byte(body), securityTXTTestNow)
}

func hasSecurityTXTIssue(ob *SecurityTXTObservation, issue string) bool {
	for _, value := range ob.Issues {
		if value == issue {
			return true
		}
	}
	return false
}

func TestSecurityTXTValidSummaryAndRedaction(t *testing.T) {
	ob := parseSecurityTXTTest("# Disclosure contact: 私たち\r\n \t \r\ncontact: mailto:private-security@example.com\r\nContact: https://example.com/secret-contact?token=SECRET_CONTACT_TOKEN\r\nExpires: 2027-01-01t01:00:00+01:00\r\nCanonical: https://EXAMPLE.COM:443/.well-known/security.txt\r\nCanonical: https://other.example/.well-known/security.txt\r\nUnknown-Extension: ignored PRIVATE_EXTENSION\r\n")
	if ob.Status != "present" || ob.ContactCount != 2 || ob.Expires != "2027-01-01T00:00:00Z" || !ob.CanonicalPresent || !ob.CanonicalMatches || ob.Signed || len(ob.Issues) != 0 {
		t.Fatalf("valid summary: %#v", ob)
	}
	encoded, err := json.Marshal(ob)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"private-security", "secret-contact", "SECRET_CONTACT_TOKEN", "PRIVATE_EXTENSION", "other.example", "私たち"} {
		if strings.Contains(string(encoded), excluded) {
			t.Fatalf("excluded text persisted: %s", excluded)
		}
	}
}

func TestSecurityTXTHTTPStatusAndBounds(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{{404, "absent"}, {410, "absent"}, {301, "redirect"}, {302, "redirect"}, {304, "redirect"}, {399, "redirect"}, {401, "unassessed"}, {500, "unassessed"}, {206, "unassessed"}, {204, "unassessed"}} {
		ob := ParseSecurityTXT(securityTXTTestURL, tc.code, "", nil, securityTXTTestNow)
		if ob.Status != tc.want || ob.ContactCount != 0 {
			t.Fatalf("status %d: %#v", tc.code, ob)
		}
	}
	ob := parseSecurityTXTTest(strings.Repeat("x", maxSecurityTXTBytes+1))
	if ob.Status != "unassessed" || !hasSecurityTXTIssue(ob, "BODY_LIMIT") {
		t.Fatalf("oversized response: %#v", ob)
	}
	body := "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n#"
	body += strings.Repeat("x", maxSecurityTXTBytes-len(body)-1) + "\n"
	if ob := parseSecurityTXTTest(body); ob.Status != "present" {
		t.Fatalf("exact size limit rejected: %#v", ob)
	}
}

func TestSecurityTXTMalformedAndRequiredFields(t *testing.T) {
	validContact := "Contact: mailto:security@example.com\n"
	validExpires := "Expires: 2027-01-01T00:00:00Z\n"
	for _, tc := range []struct{ name, body, issue string }{
		{"empty", "", "CONTACT_REQUIRED"},
		{"no contact", validExpires, "CONTACT_REQUIRED"},
		{"bare email", "Contact: security@example.com\n" + validExpires, "CONTACT_URI"},
		{"http contact", "Contact: http://example.com/security\n" + validExpires, "CONTACT_URI"},
		{"empty host", "Contact: https:///security\n" + validExpires, "CONTACT_URI"},
		{"bad URI escape", "Contact: mailto:bad%ZZ@example.com\n" + validExpires, "CONTACT_URI"},
		{"no expires", validContact, "EXPIRES_REQUIRED_ONCE"},
		{"duplicate expires", validContact + validExpires + validExpires, "EXPIRES_REQUIRED_ONCE"},
		{"bad date", validContact + "Expires: next year\n", "EXPIRES_DATE"},
		{"invalid offset", validContact + "Expires: 2027-01-01T00:00:00+24:00\n", "EXPIRES_DATE"},
		{"comma fraction", validContact + "Expires: 2027-01-01T00:00:00,5Z\n", "EXPIRES_DATE"},
		{"bad syntax", validContact + validExpires + "no-colon\n", "SYNTAX"},
		{"control byte", validContact + validExpires + "#\x00\n", "SYNTAX"},
		{"missing newline", validContact + strings.TrimSuffix(validExpires, "\n"), "LINE_ENDING"},
		{"bare carriage return", validContact + validExpires + "#bad\rline\n", "LINE_ENDING"},
		{"invalid UTF8", validContact + validExpires + string([]byte{0xff}), "UTF8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ob := parseSecurityTXTTest(tc.body)
			if ob.Status != "invalid" || !hasSecurityTXTIssue(ob, tc.issue) {
				t.Fatalf("want invalid/%s, got %#v", tc.issue, ob)
			}
			if tc.name == "duplicate expires" && ob.Expires != "" {
				t.Fatal("selected one ambiguous expiry")
			}
		})
	}
}

func TestSecurityTXTMIMEAndSignature(t *testing.T) {
	body := []byte("Contact: tel:+1-201-555-0123\nExpires: 2027-01-01T00:00:00z\n")
	for _, contentType := range []string{"text/plain", "text/plain; charset=UTF-8", "TEXT/PLAIN"} {
		if ob := ParseSecurityTXT(securityTXTTestURL, 200, contentType, body, securityTXTTestNow); ob.Status != "present" {
			t.Fatalf("valid MIME %q: %#v", contentType, ob)
		}
	}
	for _, contentType := range []string{"", "text/html", "text/plain; charset=iso-8859-1", "text/plain; charset=\"\"", "text/plain, text/html"} {
		ob := ParseSecurityTXT(securityTXTTestURL, 200, contentType, body, securityTXTTestNow)
		if ob.Status != "invalid" || !hasSecurityTXTIssue(ob, "CONTENT_TYPE") {
			t.Fatalf("invalid MIME %q: %#v", contentType, ob)
		}
	}
	ob := parseSecurityTXTTest("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:secret@example.com\nExpires: 2027-01-01T00:00:00Z\n-----BEGIN PGP SIGNATURE-----\nunverified\n")
	if ob.Status != "unassessed" || !ob.Signed || ob.ContactCount != 0 || !hasSecurityTXTIssue(ob, "SIGNATURE_UNVERIFIED") {
		t.Fatalf("unverified signature treated as trusted data: %#v", ob)
	}
}

func TestSecurityTXTCanonicalScopeAndExpiryBoundary(t *testing.T) {
	body := "Contact: mailto:security@example.com\nExpires: 2026-10-04T12:00:00Z\n"
	ob := parseSecurityTXTTest(body)
	if ob.Status != "present" || !hasSecurityTXTIssue(ob, "EXPIRED") || ob.CanonicalPresent {
		t.Fatalf("expiry boundary/optional canonical: %#v", ob)
	}
	for _, canonical := range []string{"https://sub.example.com/.well-known/security.txt", "https://example.com/security.txt", securityTXTTestURL + "?token=SECRET", "http://example.com/.well-known/security.txt", "https://example.com/.well-known/%73ecurity.txt"} {
		ob := parseSecurityTXTTest(body + "Canonical: " + canonical + "\n")
		if ob.Status != "unassessed" || !ob.CanonicalPresent || ob.CanonicalMatches || !hasSecurityTXTIssue(ob, "CANONICAL_MISMATCH") {
			t.Fatalf("mismatched canonical %q: %#v", canonical, ob)
		}
	}
	for _, target := range []string{"https://example.com/private/SECRET", "https://user:SECRET@example.com/.well-known/security.txt", securityTXTTestURL + "?token=SECRET"} {
		ob := ParseSecurityTXT(target, 200, "text/plain", []byte(body), securityTXTTestNow)
		if ob.Status != "unassessed" || ob.URL != "" || !hasSecurityTXTIssue(ob, "INVALID_TARGET") {
			t.Fatalf("invalid target leaked or accepted: %#v", ob)
		}
	}
}
