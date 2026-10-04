package inspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxHeaderBytes = 32768
const maxDNSRecords = 64
const maxDNSRecordBytes = 8192
const maxDNSBytes = 32768

type DNSResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupTXT(context.Context, string) ([]string, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupCNAME(context.Context, string) (string, error)
}

type Collector struct {
	Resolver    DNSResolver
	DialContext func(context.Context, string, string) (net.Conn, error)
	Now         func() time.Time
	rootCAs     *x509.CertPool
}

func NewCollector() *Collector {
	return &Collector{Resolver: &net.Resolver{PreferGo: true, StrictErrors: true}, DialContext: (&net.Dialer{}).DialContext, Now: time.Now}
}

var blockedPrefixes = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	result := make([]netip.Prefix, len(values))
	for i, value := range values {
		result[i] = netip.MustParsePrefix(value)
	}
	return result
}()

var globalIPv6 = netip.MustParsePrefix("2000::/3")

func IsPublicAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() || (!address.Is4() && !globalIPv6.Contains(address)) {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

type networkFailure struct{ code, message string }

func (e *networkFailure) Error() string { return e.message }

func failNetwork(code, message string) error { return &networkFailure{code: code, message: message} }

func safeNetworkError(target string, err error) CheckError {
	var failure *networkFailure
	if errors.As(err, &failure) {
		return CheckError{Target: target, Code: failure.code, Message: failure.message}
	}
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	var verification *tls.CertificateVerificationError
	var netError net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return CheckError{Target: target, Code: "CANCELED", Message: "The check was canceled."}
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()):
		return CheckError{Target: target, Code: "ETIMEDOUT", Message: "The network operation exceeded its deadline."}
	case errors.As(err, &hostname):
		return CheckError{Target: target, Code: "TLS_CERTIFICATE_INVALID", Message: "The TLS certificate does not match the requested hostname."}
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired && time.Now().After(invalid.Cert.NotAfter) {
			return CheckError{Target: target, Code: "TLS_CERTIFICATE_INVALID", Message: "The TLS certificate has expired."}
		}
		return CheckError{Target: target, Code: "TLS_CERTIFICATE_INVALID", Message: "The TLS certificate is not valid for this connection."}
	case errors.As(err, &authority):
		return CheckError{Target: target, Code: "TLS_CERTIFICATE_INVALID", Message: "The TLS certificate chain could not be verified."}
	case errors.As(err, &verification):
		return CheckError{Target: target, Code: "TLS_CERTIFICATE_INVALID", Message: "TLS certificate verification failed."}
	default:
		return CheckError{Target: target, Code: "NETWORK_ERROR", Message: "The network check could not complete."}
	}
}

func dnsResult(records []string, err error) DNSResult {
	result := DNSResult{Status: "absent", Records: []string{}}
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) && dnsError.IsNotFound {
			return result
		}
		result.Status = "error"
		result.Error = safeNetworkError("", err).Code
		return result
	}
	size := 0
	for _, record := range records {
		size += len(record)
		if len(record) > maxDNSRecordBytes || size > maxDNSBytes {
			return DNSResult{Status: "error", Records: []string{}, Error: "DNS_LIMIT"}
		}
	}
	if len(records) > maxDNSRecords {
		return DNSResult{Status: "error", Records: []string{}, Error: "DNS_LIMIT"}
	}
	if len(records) > 0 {
		result.Status, result.Records = "ok", append([]string{}, records...)
		sort.Strings(result.Records)
	}
	return result
}

func filterRecords(result DNSResult, expression *regexp.Regexp) DNSResult {
	if result.Status == "error" {
		return result
	}
	filtered := make([]string, 0, len(result.Records))
	for _, record := range result.Records {
		if expression.MatchString(record) {
			filtered = append(filtered, record)
		}
	}
	return dnsResult(filtered, nil)
}

var spfVersion = regexp.MustCompile(`(?i)^v=spf1(?:\s|$)`)
var dmarcVersion = regexp.MustCompile(`(?i)^v\s*=\s*DMARC1(?:;|\s|$)`)

func (c *Collector) resolve(ctx context.Context, hostname string, includeMail, includeDetails bool) *DNSObservation {
	resolver := c.Resolver
	if resolver == nil {
		resolver = &net.Resolver{PreferGo: true, StrictErrors: true}
	}
	skipped := func() DNSResult { return DNSResult{Status: "skipped", Records: []string{}} }
	dns := &DNSObservation{SPF: skipped(), DMARC: skipped(), MX: skipped()}
	var wg sync.WaitGroup
	ipQuery := func(network string, output *DNSResult) {
		defer wg.Done()
		addresses, err := resolver.LookupIP(ctx, network, hostname)
		records := make([]string, 0, len(addresses))
		for _, address := range addresses {
			parsed, ok := netip.AddrFromSlice(address)
			if !ok || (network == "ip4" && !parsed.Unmap().Is4()) || (network == "ip6" && (parsed.Is4() || parsed.Is4In6())) {
				err = failNetwork("DNS_INVALID_ADDRESS", "Address response did not match the requested record type.")
				break
			}
			if network == "ip4" {
				parsed = parsed.Unmap()
			}
			records = append(records, parsed.String())
		}
		*output = dnsResult(records, err)
	}
	wg.Add(2)
	go ipQuery("ip4", &dns.A)
	go ipQuery("ip6", &dns.AAAA)
	if includeMail {
		wg.Add(3)
		go func() {
			defer wg.Done()
			records, err := resolver.LookupTXT(ctx, hostname)
			dns.SPF = filterRecords(dnsResult(records, err), spfVersion)
		}()
		go func() {
			defer wg.Done()
			records, err := resolver.LookupTXT(ctx, "_dmarc."+hostname)
			dns.DMARC = filterRecords(dnsResult(records, err), dmarcVersion)
		}()
		go func() {
			defer wg.Done()
			mx, err := resolver.LookupMX(ctx, hostname)
			records := make([]string, 0, len(mx))
			for _, value := range mx {
				if value == nil {
					err = failNetwork("DNS_INVALID_RECORD", "The resolver returned an invalid MX record.")
					break
				}
				records = append(records, strconv.Itoa(int(value.Pref))+" "+value.Host)
			}
			dns.MX = dnsResult(records, err)
		}()
	}
	if includeDetails {
		dns.NS, dns.CNAME = &DNSResult{}, &DNSResult{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			nameservers, err := resolver.LookupNS(ctx, hostname)
			records := make([]string, 0, len(nameservers))
			for _, nameserver := range nameservers {
				if nameserver == nil || !validDNSName(nameserver.Host) {
					err = failNetwork("DNS_INVALID_RECORD", "The resolver returned an invalid NS record.")
					break
				}
				records = append(records, strings.ToLower(nameserver.Host))
			}
			*dns.NS = dnsResult(records, err)
		}()
		go func() {
			defer wg.Done()
			canonical, err := resolver.LookupCNAME(ctx, hostname)
			records := []string{}
			if err == nil {
				if !validDNSName(canonical) {
					err = failNetwork("DNS_INVALID_RECORD", "The resolver returned an invalid canonical name.")
				} else if !strings.EqualFold(strings.TrimSuffix(canonical, "."), hostname) {
					// LookupCNAME returns the final resolver result, not the alias chain.
					records = append(records, strings.ToLower(canonical))
				}
			}
			*dns.CNAME = dnsResult(records, err)
		}()
	}
	wg.Wait()
	return dns
}

func validDNSName(value string) bool {
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
				return false
			}
		}
	}
	return true
}

func addressMatches(connection net.Conn, expected netip.Addr) bool {
	host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err != nil {
		return false
	}
	actual, err := netip.ParseAddr(host)
	return err == nil && actual.Unmap() == expected.Unmap()
}

var retainedHeaders = map[string]bool{
	"content-type": true, "strict-transport-security": true, "content-security-policy": true,
	"content-security-policy-report-only": true, "x-content-type-options": true, "x-frame-options": true,
	"referrer-policy": true, "permissions-policy": true,
}

func (c *Collector) requestResponse(ctx context.Context, target, address string) (*http.Response, func(), error) {
	if !IsPublicAddress(address) {
		return nil, nil, failNetwork("DESTINATION_BLOCKED", "The connection address is not public.")
	}
	normalized, err := NormalizeTarget(target)
	if err != nil {
		return nil, nil, failNetwork("INVALID_TARGET", "The request target is not a valid HTTPS URL.")
	}
	target = normalized
	u, _ := url.Parse(normalized)
	expected, _ := netip.ParseAddr(address)
	dial := c.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: maxHeaderBytes,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: c.rootCAs},
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			connection, err := dial(dialCtx, "tcp", net.JoinHostPort(expected.String(), "443"))
			if err != nil {
				return nil, err
			}
			if !addressMatches(connection, expected) {
				connection.Close()
				return nil, failNetwork("TLS_DESTINATION_MISMATCH", "The connection did not reach the validated destination.")
			}
			return connection, nil
		},
	}
	cleanup := func() { transport.CloseIdleConnections() }
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Inspectyn/"+Version)
	req.Header.Set("Accept", "*/*")
	req.Close = true
	response, err := client.Do(req)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	cleanup = func() {
		response.Body.Close()
		transport.CloseIdleConnections()
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
		cleanup()
		return nil, nil, failNetwork("TLS_DESTINATION_MISMATCH", "The connection did not provide a verified TLS certificate.")
	}
	return response, cleanup, nil
}

func (c *Collector) request(ctx context.Context, target, address string) (*HTTPObservation, *TLSObservation, error) {
	response, cleanup, err := c.requestResponse(ctx, target, address)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()
	headers := make(map[string][]string)
	for name, values := range response.Header {
		lower := strings.ToLower(name)
		if retainedHeaders[lower] {
			headers[lower] = append([]string{}, values...)
		}
	}
	return &HTTPObservation{Status: response.StatusCode, Headers: headers, Cookies: CaptureCookies(response.Header)}, observeTLS(response.TLS), nil
}

func (c *Collector) requestSecurityTXT(ctx context.Context, target, address string, now time.Time) (*SecurityTXTObservation, error) {
	failure := func(code string, status int) *SecurityTXTObservation {
		return &SecurityTXTObservation{URL: target, Status: "error", HTTPStatus: status, Issues: []string{code}}
	}
	response, cleanup, err := c.requestResponse(ctx, target, address)
	if err != nil {
		return failure(safeNetworkError(target, err).Code, 0), err
	}
	defer cleanup()
	contentTypes := response.Header.Values("Content-Type")
	contentType := ""
	if response.StatusCode == http.StatusOK && len(contentTypes) > 1 {
		return failure("AMBIGUOUS_CONTENT_TYPE", response.StatusCode), failNetwork("SECURITY_TXT_INCOMPLETE", "The security.txt response has ambiguous content types.")
	}
	if len(contentTypes) == 1 {
		contentType = contentTypes[0]
	}
	var body []byte
	if response.StatusCode == http.StatusOK {
		body, err = io.ReadAll(io.LimitReader(response.Body, maxSecurityTXTBytes+1))
		if err != nil {
			return failure("BODY_READ_FAILED", response.StatusCode), err
		}
		if len(body) > maxSecurityTXTBytes {
			return failure("BODY_LIMIT", response.StatusCode), failNetwork("SECURITY_TXT_INCOMPLETE", "The security.txt response exceeds the body limit.")
		}
		if !utf8.Valid(body) {
			return failure("INVALID_UTF8", response.StatusCode), failNetwork("SECURITY_TXT_INCOMPLETE", "The security.txt response is not valid UTF-8.")
		}
	}
	return ParseSecurityTXT(target, response.StatusCode, contentType, body, now), nil
}

func (c *Collector) Collect(ctx context.Context, target string, config Config, kind string) (Observation, []CheckError) {
	var normalized string
	var err error
	switch kind {
	case "scan":
		normalized, err = NormalizeTarget(target)
	case "recon":
		normalized, err = NormalizeReconTarget(target)
	default:
		err = fmt.Errorf("unsupported collection kind")
	}
	if err != nil {
		return Observation{}, []CheckError{{Target: target, Code: "INVALID_TARGET", Message: "Target or collection mode is invalid."}}
	}
	u, _ := url.Parse(normalized)
	now := c.Now
	if now == nil {
		now = time.Now
	}
	observation := Observation{URL: normalized, Hostname: u.Hostname(), ObservedAt: now().UTC().Format(time.RFC3339Nano), Addresses: []string{}}
	errorsFound := []CheckError{}
	timeout := time.Duration(config.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dnsCtx, cancelDNS := context.WithTimeout(ctx, timeout)
	observation.DNS = c.resolve(dnsCtx, u.Hostname(), config.DNS, config.DNSDetails)
	cancelDNS()
	for _, entry := range []struct {
		name string
		data DNSResult
	}{{"A", observation.DNS.A}, {"AAAA", observation.DNS.AAAA}, {"SPF", observation.DNS.SPF}, {"DMARC", observation.DNS.DMARC}, {"MX", observation.DNS.MX}} {
		if entry.data.Status == "error" {
			errorsFound = append(errorsFound, CheckError{Target: normalized, Code: "DNS_CHECK_INCOMPLETE", Message: entry.name + " DNS evidence could not be retrieved."})
		}
	}
	for _, entry := range []struct {
		name string
		data *DNSResult
	}{{"NS", observation.DNS.NS}, {"canonical name", observation.DNS.CNAME}} {
		if entry.data != nil && entry.data.Status == "error" {
			errorsFound = append(errorsFound, CheckError{Target: normalized, Code: "DNS_CHECK_INCOMPLETE", Message: entry.name + " DNS evidence could not be retrieved."})
		}
	}
	seen := map[string]bool{}
	for _, address := range append(append([]string{}, observation.DNS.A.Records...), observation.DNS.AAAA.Records...) {
		if !seen[address] {
			observation.Addresses = append(observation.Addresses, address)
			seen[address] = true
		}
	}
	addressFailure := observation.DNS.A.Status == "error" || observation.DNS.AAAA.Status == "error"
	if !addressFailure && len(observation.Addresses) == 0 {
		errorsFound = append(errorsFound, CheckError{Target: normalized, Code: "DNS_NO_ADDRESS", Message: "No A or AAAA address was returned."})
	}
	if kind == "recon" || addressFailure || len(observation.Addresses) == 0 {
		return observation, errorsFound
	}
	for _, address := range observation.Addresses {
		if !IsPublicAddress(address) {
			return observation, append(errorsFound, CheckError{Target: normalized, Code: "DESTINATION_BLOCKED", Message: "The hostname resolves to a private, reserved or unsupported address; no HTTPS request was made."})
		}
	}
	observation.Address = observation.Addresses[0]
	httpCtx, cancelHTTP := context.WithTimeout(ctx, timeout)
	observation.HTTP, observation.TLS, err = c.request(httpCtx, normalized, observation.Address)
	cancelHTTP()
	if err != nil {
		errorsFound = append(errorsFound, safeNetworkError(normalized, err))
	}
	if config.SecurityTXT {
		securityURL := "https://" + u.Host + "/.well-known/security.txt"
		securityCtx, cancelSecurity := context.WithTimeout(ctx, timeout)
		observation.SecurityTXT, err = c.requestSecurityTXT(securityCtx, securityURL, observation.Address, now())
		cancelSecurity()
		if err != nil {
			errorsFound = append(errorsFound, CheckError{Target: normalized, Code: "SECURITY_TXT_INCOMPLETE", Message: "The security.txt check could not complete."})
		}
	}
	return observation, errorsFound
}
