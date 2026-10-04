package inspect

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const maxObservedCookies = 64
const maxObservedCookieName = 256

var foldedCookiePair = regexp.MustCompile(",[ \\t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \\t]*=")

// CaptureCookies keeps only attribute metadata. Cookie values, raw headers,
// domain strings, and path strings must never enter an observation or error.
// Each Set-Cookie field is parsed separately: commas are not a safe separator.
func CaptureCookies(headers http.Header) *CookieObservation {
	ob := &CookieObservation{Status: "ok", Items: []CookieAttributes{}}
	keys := []string{}
	for key := range headers {
		if strings.EqualFold(key, "Set-Cookie") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, raw := range headers[key] {
			ob.Total++
			if ob.Total > maxObservedCookies {
				ob.Invalid++ // Includes fields not assessed because of the limit.
				continue
			}
			cookie, err := http.ParseSetCookie(raw)
			if err != nil || len(cookie.Name) > maxObservedCookieName || len(cookie.Name)+len(cookie.Value) > 4096 || ambiguousCookieAttributes(raw) {
				ob.Invalid++
				continue
			}
			unparsedKnownAttribute := false
			for _, part := range cookie.Unparsed {
				name, _, _ := strings.Cut(part, "=")
				if cookieSecurityAttribute(strings.ToLower(strings.TrimSpace(name))) {
					unparsedKnownAttribute = true
				}
			}
			if unparsedKnownAttribute {
				ob.Invalid++
				continue
			}
			// Cookie.Valid also checks Domain and Path syntax. Partitioned's
			// Secure requirement is a configuration check, not a parse failure.
			validationCopy := *cookie
			validationCopy.Partitioned = false
			if validationCopy.Valid() != nil {
				ob.Invalid++
				continue
			}
			sameSite := "unspecified"
			switch cookie.SameSite {
			case http.SameSiteLaxMode:
				sameSite = "lax"
			case http.SameSiteStrictMode:
				sameSite = "strict"
			case http.SameSiteNoneMode:
				sameSite = "none"
			case http.SameSiteDefaultMode:
				// An unrecognized explicit value is not an absent attribute.
				ob.Invalid++
				continue
			}
			ob.Items = append(ob.Items, CookieAttributes{
				Index: ob.Total, Name: cookie.Name, Secure: cookie.Secure,
				HTTPOnly: cookie.HttpOnly, SameSite: sameSite,
				DomainScoped: cookieAttributePresent(raw, "domain"), PathRoot: cookie.Path == "/",
				Partitioned: cookie.Partitioned,
			})
		}
	}
	if ob.Invalid > 0 {
		ob.Status = "error"
	}
	return ob
}

func cookieSecurityAttribute(name string) bool {
	switch name {
	case "secure", "httponly", "samesite", "domain", "path", "partitioned":
		return true
	default:
		return false
	}
}

func cookieAttributePresent(raw, attribute string) bool {
	for _, part := range strings.Split(raw, ";")[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(name, attribute) {
			return true
		}
	}
	return false
}

func ambiguousCookieAttributes(raw string) bool {
	parts := strings.Split(raw, ";")
	// Go accepts commas in values, but a folded Set-Cookie field can then look
	// like one cookie. Do not infer attributes from this ambiguous representation.
	if strings.Contains(parts[0], ",") || foldedCookiePair.MatchString(raw) {
		return true
	}
	seen := map[string]bool{}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		name, value, hasValue := strings.Cut(part, "=")
		normalized := strings.ToLower(strings.TrimSpace(name))
		if !cookieSecurityAttribute(normalized) {
			continue // Unknown extension attributes do not invalidate a cookie.
		}
		if seen[normalized] || name != strings.TrimSpace(name) {
			return true
		}
		seen[normalized] = true
		// A rejected security attribute could otherwise appear to be absent.
		for _, ch := range value {
			if ch < 0x20 || ch >= 0x7f || ch == '"' || ch == '\\' || (ch == ',' && normalized != "expires") {
				return true
			}
		}
		if normalized == "samesite" {
			if !hasValue || !(strings.EqualFold(value, "lax") || strings.EqualFold(value, "strict") || strings.EqualFold(value, "none")) {
				return true
			}
		}
		if normalized == "domain" && (!hasValue || strings.TrimSpace(value) == "") {
			return true
		}
		if normalized == "path" && !hasValue {
			return true
		}
	}
	return false
}
