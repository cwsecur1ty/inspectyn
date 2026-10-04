package inspect

import (
	"bytes"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const maxSecurityTXTBytes = 64 * 1024

var securityTXTDate = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)

// ParseSecurityTXT performs a bounded syntax and freshness assessment of an
// unsigned security.txt response. It does not fetch contacts, verify signatures,
// establish ownership, or claim full RFC 9116 compliance. Only safe summary
// fields and fixed issue codes survive; contact URIs and raw text never do.
func ParseSecurityTXT(targetURL string, httpStatus int, contentType string, body []byte, now time.Time) *SecurityTXTObservation {
	ob := &SecurityTXTObservation{Status: "unassessed", HTTPStatus: httpStatus, Issues: []string{}}
	target, err := NormalizeTarget(targetURL)
	if err != nil {
		ob.Issues = append(ob.Issues, "INVALID_TARGET")
		return ob
	}
	u, _ := url.Parse(target)
	if u.EscapedPath() != "/.well-known/security.txt" {
		ob.Issues = append(ob.Issues, "INVALID_TARGET")
		return ob
	}
	ob.URL = target
	switch {
	case httpStatus == 404 || httpStatus == 410:
		ob.Status = "absent"
		return ob
	case httpStatus >= 300 && httpStatus < 400:
		ob.Status = "redirect"
		ob.Issues = append(ob.Issues, "REDIRECT_NOT_FOLLOWED")
		return ob
	case httpStatus != 200:
		ob.Issues = append(ob.Issues, "HTTP_STATUS")
		return ob
	}
	if len(body) > maxSecurityTXTBytes {
		ob.Issues = append(ob.Issues, "BODY_LIMIT")
		return ob
	}
	if bytes.Contains(body, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) || bytes.Contains(body, []byte("-----BEGIN PGP SIGNATURE-----")) {
		ob.Signed = true
		ob.Issues = append(ob.Issues, "SIGNATURE_UNVERIFIED")
		return ob
	}
	addIssue := func(code string) {
		for _, existing := range ob.Issues {
			if existing == code {
				return
			}
		}
		ob.Issues = append(ob.Issues, code)
	}
	mediaType, parameters, mimeErr := mime.ParseMediaType(contentType)
	charset, hasCharset := parameters["charset"]
	if mimeErr != nil || !strings.EqualFold(mediaType, "text/plain") || (hasCharset && !strings.EqualFold(charset, "utf-8")) {
		addIssue("CONTENT_TYPE")
	}
	if !utf8.Valid(body) {
		addIssue("UTF8")
		ob.Status = "invalid"
		return ob
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	if !strings.HasSuffix(text, "\n") || strings.ContainsRune(text, '\r') {
		addIssue("LINE_ENDING")
	}
	if strings.IndexFunc(text, func(ch rune) bool { return (ch < 0x20 && ch != '\t' && ch != '\n') || ch == 0x7f }) >= 0 {
		addIssue("SYNTAX")
	}
	expiresCount := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.Trim(line, " \t") == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found || !securityTXTFieldName(name) || strings.TrimSpace(value) == "" {
			addIssue("SYNTAX")
			continue
		}
		value = strings.Trim(value, " \t")
		switch strings.ToLower(name) {
		case "contact":
			if securityTXTContactURI(value) {
				ob.ContactCount++
			} else {
				addIssue("CONTACT_URI")
			}
		case "expires":
			expiresCount++
			date, dateErr := time.Parse(time.RFC3339Nano, strings.ToUpper(value))
			if !securityTXTDate.MatchString(value) || dateErr != nil {
				addIssue("EXPIRES_DATE")
			} else if expiresCount == 1 {
				ob.Expires = date.UTC().Format(time.RFC3339Nano)
				if !date.After(now) {
					addIssue("EXPIRED")
				}
			}
		case "canonical":
			ob.CanonicalPresent = true
			canonical, normalizeErr := NormalizeTarget(value)
			if normalizeErr == nil && canonical == target {
				ob.CanonicalMatches = true
			}
		default:
			// Unsupported optional fields are deliberately ignored (RFC 9116).
		}
	}
	if ob.ContactCount == 0 {
		addIssue("CONTACT_REQUIRED")
	}
	if expiresCount != 1 {
		addIssue("EXPIRES_REQUIRED_ONCE")
		ob.Expires = "" // Do not select one date from conflicting declarations.
	}
	ob.Status = "present"
	for _, issue := range ob.Issues {
		if issue != "EXPIRED" {
			ob.Status = "invalid"
		}
	}
	if ob.CanonicalPresent && !ob.CanonicalMatches {
		ob.Status = "unassessed"
		addIssue("CANONICAL_MISMATCH")
	}
	return ob
}

func securityTXTFieldName(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < 33 || ch > 126 || ch == ':' {
			return false
		}
	}
	return true
}

// Validate URI syntax only. No scheme-specific deliverability or remote
// availability is inferred, and no URI is followed or retained.
func securityTXTContactURI(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch <= 0x20 || ch >= 0x7f || strings.ContainsRune(`"<>\^`+"`"+`{|}`, ch) {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.User != nil {
		return false
	}
	if _, err := url.PathUnescape(value); err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return false // RFC 9116 requires HTTPS for web contact URIs.
	case "https":
		return u.Hostname() != "" && u.Opaque == ""
	default:
		return u.Opaque != "" || u.Host != "" || u.Path != ""
	}
}
