package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	ip    func(context.Context, string, string) ([]net.IP, error)
	txt   func(context.Context, string) ([]string, error)
	mx    func(context.Context, string) ([]*net.MX, error)
	ns    func(context.Context, string) ([]*net.NS, error)
	cname func(context.Context, string) (string, error)
	mu    sync.Mutex
	calls []string
}

func (r *fakeResolver) remember(value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, value)
}

func (r *fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	r.remember(network + " " + host)
	if r.ip != nil {
		return r.ip(ctx, network, host)
	}
	if network == "ip4" {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	return []net.IP{}, nil
}

func (r *fakeResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	r.remember("txt " + host)
	if r.txt != nil {
		return r.txt(ctx, host)
	}
	if strings.HasPrefix(host, "_dmarc.") {
		return []string{"v=DMARC1; p=reject"}, nil
	}
	return []string{"v=spf1 -all", "other-verification-record"}, nil
}

func (r *fakeResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	r.remember("mx " + host)
	if r.mx != nil {
		return r.mx(ctx, host)
	}
	return []*net.MX{{Host: "mail.company.com.", Pref: 10}}, nil
}

func (r *fakeResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	r.remember("ns " + host)
	if r.ns != nil {
		return r.ns(ctx, host)
	}
	return []*net.NS{{Host: "ns1.company.com."}}, nil
}

func (r *fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	r.remember("cname " + host)
	if r.cname != nil {
		return r.cname(ctx, host)
	}
	return host + ".", nil
}

func TestPublicAddressBoundary(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "10.2.3.4", "100.64.1.1", "127.0.0.1", "169.254.169.254", "172.31.4.5", "192.168.1.1", "192.0.0.9", "192.0.2.1", "198.18.0.1", "198.51.100.2", "203.0.113.2", "224.0.0.1", "255.255.255.255", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2001:db8::1", "2002:0808:0808::1", "3fff::1", "2606:4700::1%eth0", "invalid"} {
		if IsPublicAddress(address) {
			t.Errorf("accepted %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublicAddress(address) {
			t.Errorf("rejected %s", address)
		}
	}
}

func TestReconNeverDialsAndQueriesOnlyExactHost(t *testing.T) {
	resolver := &fakeResolver{ip: func(_ context.Context, family, _ string) ([]net.IP, error) {
		if family == "ip4" {
			return []net.IP{net.ParseIP("10.1.2.3")}, nil
		}
		return []net.IP{net.ParseIP("2606:4700:4700:0:0:0:0:1111")}, nil
	}}
	collector := &Collector{Resolver: resolver, DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("recon attempted endpoint contact")
		return nil, nil
	}}
	observation, failures := collector.Collect(context.Background(), "company.com", DefaultConfig(), "recon")
	if len(failures) != 0 || observation.HTTP != nil || observation.TLS != nil || observation.Address != "" {
		t.Fatalf("unexpected result: %+v %+v", observation, failures)
	}
	if !reflect.DeepEqual(observation.Addresses, []string{"10.1.2.3", "2606:4700:4700::1111"}) {
		t.Fatalf("address evidence: %v", observation.Addresses)
	}
	if !reflect.DeepEqual(observation.DNS.SPF.Records, []string{"v=spf1 -all"}) {
		t.Fatalf("SPF evidence: %+v", observation.DNS.SPF)
	}
	sort.Strings(resolver.calls)
	want := []string{"ip4 company.com", "ip6 company.com", "mx company.com", "txt _dmarc.company.com", "txt company.com"}
	if !reflect.DeepEqual(resolver.calls, want) {
		t.Fatalf("queries: %v", resolver.calls)
	}
}

func TestScanRejectsMixedAndIncompleteAddressAnswersBeforeContact(t *testing.T) {
	for name, lookup := range map[string]func(context.Context, string, string) ([]net.IP, error){
		"private": func(_ context.Context, family, _ string) ([]net.IP, error) {
			if family == "ip4" {
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			}
			return []net.IP{net.ParseIP("::1")}, nil
		},
		"failed": func(_ context.Context, family, _ string) ([]net.IP, error) {
			if family == "ip4" {
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			}
			return nil, &net.DNSError{Err: "server failure"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			collector := &Collector{Resolver: &fakeResolver{ip: lookup}, DialContext: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("unsafe address contacted")
				return nil, nil
			}}
			config := DefaultConfig()
			config.SecurityTXT = true
			observation, failures := collector.Collect(context.Background(), "https://company.com", config, "scan")
			if len(failures) == 0 || observation.HTTP != nil || observation.DNS.SPF.Status != "ok" {
				t.Fatalf("partial evidence lost: %+v %+v", observation, failures)
			}
			want := "DESTINATION_BLOCKED"
			if name == "failed" {
				want = "DNS_CHECK_INCOMPLETE"
			}
			if failures[0].Code != want {
				t.Fatalf("error = %+v", failures)
			}
		})
	}
}

func TestDNSStatusBoundsAndMailOptOut(t *testing.T) {
	resolver := &fakeResolver{txt: func(_ context.Context, host string) ([]string, error) {
		if strings.HasPrefix(host, "_dmarc") {
			return nil, &net.DNSError{IsNotFound: true}
		}
		return nil, &net.DNSError{IsTimeout: true, Err: "SECRET"}
	}}
	collector := &Collector{Resolver: resolver}
	observation, failures := collector.Collect(context.Background(), "company.com", DefaultConfig(), "recon")
	if observation.DNS.DMARC.Status != "absent" || observation.DNS.SPF.Status != "error" || len(failures) != 1 {
		t.Fatalf("status = %+v %+v", observation.DNS, failures)
	}
	if strings.Contains(failures[0].Message, "SECRET") {
		t.Fatal("raw resolver error leaked")
	}
	for _, records := range [][]string{make([]string, 65), {strings.Repeat("x", 8193)}, {strings.Repeat("x", 8192), strings.Repeat("x", 8192), strings.Repeat("x", 8192), strings.Repeat("x", 8192), "x"}} {
		if result := dnsResult(records, nil); result.Status != "error" || result.Error != "DNS_LIMIT" {
			t.Fatalf("unbounded result: %+v", result)
		}
	}
	config := DefaultConfig()
	config.DNS = false
	resolver = &fakeResolver{}
	collector.Resolver = resolver
	observation, failures = collector.Collect(context.Background(), "company.com", config, "recon")
	if len(failures) > 0 || observation.DNS.SPF.Status != "skipped" || observation.DNS.DMARC.Status != "skipped" || observation.DNS.MX.Status != "skipped" || len(resolver.calls) != 2 {
		t.Fatalf("mail opt-out failed: %+v %v", observation, resolver.calls)
	}
}

func TestCanceledDNSRetainsCompletedEvidence(t *testing.T) {
	resolver := &fakeResolver{ip: func(ctx context.Context, family, _ string) ([]net.IP, error) {
		if family == "ip4" {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	collector := &Collector{Resolver: resolver}
	observation, failures := collector.Collect(ctx, "company.com", DefaultConfig(), "recon")
	if len(failures) != 1 || observation.DNS.A.Status != "ok" || observation.DNS.AAAA.Status != "error" {
		t.Fatalf("partial DNS: %+v %+v", observation.DNS, failures)
	}
}

type addressedConn struct {
	net.Conn
	address net.Addr
}

func (c addressedConn) RemoteAddr() net.Addr { return c.address }

func tlsFixture(t *testing.T, hostname string, handler http.Handler, dnsNames ...string) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	if len(dnsNames) == 0 {
		dnsNames = []string{hostname}
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: hostname}, DNSNames: dnsNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, roots
}

func testCollector(server *httptest.Server, roots *x509.CertPool, dialed *string) *Collector {
	return &Collector{Resolver: &fakeResolver{}, rootCAs: roots, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if dialed != nil {
			*dialed = address
		}
		connection, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return addressedConn{Conn: connection, address: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 443}}, nil
	}}
}

func TestActualTLSRequestPinsDestinationAndPreservesRepeatedHeaders(t *testing.T) {
	var calls atomic.Int32
	requestEvidence := make(chan []string, 1)
	server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		requestEvidence <- []string{r.Host, r.URL.EscapedPath(), r.TLS.ServerName, r.UserAgent()}
		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=0")
		w.Header().Add("Strict-Transport-Security", "max-age=100")
		w.Header().Set("Set-Cookie", "session=SECRET_COOKIE; Secure; HttpOnly; SameSite=Lax; Path=/")
		w.Header().Set("Location", "http://127.0.0.1/")
		w.WriteHeader(http.StatusFound)
	}))
	var dialed string
	collector := testCollector(server, roots, &dialed)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	observation, failures := collector.Collect(context.Background(), "https://company.com/a%2Fb", DefaultConfig(), "scan")
	if len(failures) > 0 {
		t.Fatalf("request failed: %+v", failures)
	}
	if calls.Load() != 1 || dialed != "8.8.8.8:443" || !observation.TLS.Authorized || observation.HTTP.Status != 302 {
		t.Fatalf("bad pinned request: %s %+v", dialed, observation)
	}
	if got := <-requestEvidence; !reflect.DeepEqual(got, []string{"company.com", "/a%2Fb", "company.com", "Inspectyn/" + Version}) {
		t.Fatalf("request identity = %v", got)
	}
	if !reflect.DeepEqual(observation.HTTP.Headers["content-type"], []string{"text/html", "application/json"}) {
		t.Fatalf("duplicate headers lost: %v", observation.HTTP.Headers)
	}
	if _, ok := observation.HTTP.Headers["set-cookie"]; ok {
		t.Fatal("cookie retained")
	}
	if _, ok := observation.HTTP.Headers["location"]; ok {
		t.Fatal("redirect destination retained")
	}
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	if observation.TLS.FingerprintSHA256 != hex.EncodeToString(fingerprint[:]) || observation.TLS.Subject != "CN=company.com" || observation.TLS.Issuer != "CN=company.com" || observation.TLS.PublicKeyAlgorithm != "ECDSA" || observation.TLS.PublicKeyBits != 256 || observation.TLS.VerifiedChainLength != 1 || observation.TLS.CipherSuite == "" || !reflect.DeepEqual(observation.TLS.DNSNames, []string{"company.com"}) {
		t.Fatalf("TLS details: %+v", observation.TLS)
	}
	if observation.TLS.ValidFrom != certificate.NotBefore.UTC().Format(time.RFC3339Nano) || observation.TLS.SerialNumber != certificate.SerialNumber.Text(16) || observation.TLS.SignatureAlgorithm != certificate.SignatureAlgorithm.String() {
		t.Fatalf("certificate identity: %+v", observation.TLS)
	}
	if observation.HTTP.Cookies == nil || observation.HTTP.Cookies.Total != 1 || observation.HTTP.Cookies.Items[0].Name != "session" {
		t.Fatalf("cookie attributes missing: %+v", observation.HTTP.Cookies)
	}
	encoded, err := json.Marshal(observation)
	if err != nil || strings.Contains(string(encoded), "SECRET_COOKIE") {
		t.Fatalf("cookie value retained: %s %v", encoded, err)
	}
}

func TestDNSDetailsOnlyQueryRequestedHostAndNeverExpandScope(t *testing.T) {
	resolver := &fakeResolver{cname: func(_ context.Context, host string) (string, error) {
		return "Service.OTHER.example.", nil
	}}
	collector := &Collector{Resolver: resolver, DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("DNS reconnaissance contacted an endpoint")
		return nil, nil
	}}
	config := DefaultConfig()
	config.DNS, config.DNSDetails = false, true
	observation, failures := collector.Collect(context.Background(), "company.com", config, "recon")
	if len(failures) != 0 || observation.DNS.NS.Status != "ok" || observation.DNS.CNAME.Status != "ok" || !reflect.DeepEqual(observation.DNS.CNAME.Records, []string{"service.other.example."}) || observation.DNS.SPF.Status != "skipped" {
		t.Fatalf("details: %+v %+v", observation.DNS, failures)
	}
	sort.Strings(resolver.calls)
	want := []string{"cname company.com", "ip4 company.com", "ip6 company.com", "ns company.com"}
	if !reflect.DeepEqual(resolver.calls, want) {
		t.Fatalf("query scope: %v", resolver.calls)
	}
	config.DNSDetails = false
	observation, failures = collector.Collect(context.Background(), "company.com", config, "recon")
	if len(failures) != 0 || observation.DNS.NS != nil || observation.DNS.CNAME != nil {
		t.Fatalf("default added detail queries: %+v %+v", observation.DNS, failures)
	}
}

func TestDNSDetailsSeparateAbsenceInvalidAndFailure(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		canonical   string
		nameservers []*net.NS
		err         error
		wantStatus  string
		wantErrors  int
	}{
		{"same-name", "COMPANY.COM.", nil, nil, "absent", 0},
		{"absent", "", nil, &net.DNSError{IsNotFound: true}, "absent", 0},
		{"error", "", nil, errors.New("SECRET_RESOLVER_ERROR"), "error", 2},
		{"invalid", "invalid name", []*net.NS{nil}, nil, "error", 2},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			resolver := &fakeResolver{
				cname: func(context.Context, string) (string, error) { return scenario.canonical, scenario.err },
				ns:    func(context.Context, string) ([]*net.NS, error) { return scenario.nameservers, scenario.err },
			}
			config := DefaultConfig()
			config.DNSDetails = true
			observation, failures := (&Collector{Resolver: resolver}).Collect(context.Background(), "company.com", config, "recon")
			if observation.DNS.CNAME.Status != scenario.wantStatus || observation.DNS.NS.Status != scenario.wantStatus || len(failures) != scenario.wantErrors || observation.DNS.CNAME.Records == nil || observation.DNS.NS.Records == nil {
				t.Fatalf("status: %+v %+v", observation.DNS, failures)
			}
			encoded, _ := json.Marshal(observation)
			if strings.Contains(string(encoded), "SECRET") {
				t.Fatal("raw DNS error exposed")
			}
		})
	}
}

func TestSecurityTXTUsesOneFixedPathAndDoesNotFollowLinks(t *testing.T) {
	paths := make(chan string, 3)
	server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.String()
		if r.URL.Path == "/.well-known/security.txt" {
			if r.Host != "company.com" || r.TLS.ServerName != "company.com" {
				t.Error("security.txt changed connection identity")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Set-Cookie", "ignored=SECRET_FROM_SECURITY_TXT")
			io.WriteString(w, "Contact: https://other.example/disclosure\nExpires: 2030-01-01T00:00:00Z\nCanonical: https://company.com/.well-known/security.txt\n")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>SECRET_BODY_NOT_RETAINED</html>")
	}))
	var dialed string
	collector := testCollector(server, roots, &dialed)
	config := DefaultConfig()
	config.SecurityTXT = true
	observation, failures := collector.Collect(context.Background(), "https://company.com/a%2Fb", config, "scan")
	if len(failures) != 0 || observation.SecurityTXT == nil || observation.SecurityTXT.Status != "present" || observation.SecurityTXT.ContactCount != 1 || !observation.SecurityTXT.CanonicalMatches || dialed != "8.8.8.8:443" {
		t.Fatalf("security.txt: %+v %+v", observation, failures)
	}
	if len(paths) != 2 || <-paths != "/a%2Fb" || <-paths != "/.well-known/security.txt" {
		t.Fatalf("unexpected request scope: %v", paths)
	}
	encoded, _ := json.Marshal(observation)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "other.example") {
		t.Fatal("response bodies, contact URLs or security.txt cookies leaked")
	}
}

func TestSecurityTXTResponseBoundsAndPartialObservations(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		status       int
		body         string
		contentTypes []string
		wantStatus   string
		wantErrors   int
	}{
		{"missing", 404, "ignored", nil, "absent", 0},
		{"missing-duplicate-type", 404, "ignored", []string{"text/plain", "text/html"}, "absent", 0},
		{"redirect", 302, "ignored", nil, "redirect", 0},
		{"server-error", 500, "ignored", nil, "unassessed", 0},
		{"large", 200, strings.Repeat("a", maxSecurityTXTBytes+1), []string{"text/plain"}, "error", 1},
		{"at-limit", 200, strings.Repeat("a", maxSecurityTXTBytes), []string{"text/plain"}, "invalid", 0},
		{"utf8", 200, "\xff", []string{"text/plain"}, "error", 1},
		{"duplicate-type", 200, "ignored", []string{"text/plain", "text/html"}, "error", 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var requests atomic.Int32
			server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/.well-known/security.txt" {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(200)
					return
				}
				for _, value := range scenario.contentTypes {
					w.Header().Add("Content-Type", value)
				}
				w.Header().Set("Location", "https://other.example/secret")
				w.WriteHeader(scenario.status)
				io.WriteString(w, scenario.body)
			}))
			config := DefaultConfig()
			config.SecurityTXT = true
			observation, failures := testCollector(server, roots, nil).Collect(context.Background(), "https://company.com/", config, "scan")
			if requests.Load() != 2 || observation.HTTP == nil || observation.TLS == nil || observation.SecurityTXT.Status != scenario.wantStatus || len(failures) != scenario.wantErrors {
				t.Fatalf("partial evidence: %+v %+v requests=%d", observation, failures, requests.Load())
			}
			if len(failures) > 0 && failures[0].Code != "SECURITY_TXT_INCOMPLETE" {
				t.Fatalf("error classification: %+v", failures)
			}
		})
	}
}

func TestSecurityTXTDeadlineAndBaseFailureAreIndependent(t *testing.T) {
	for _, timeoutPath := range []string{"/", "/.well-known/security.txt"} {
		t.Run(timeoutPath, func(t *testing.T) {
			var requests atomic.Int32
			server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == timeoutPath {
					if timeoutPath != "/" {
						w.Header().Set("Content-Type", "text/plain")
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
					}
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				io.WriteString(w, "Contact: mailto:security@company.com\nExpires: 2030-01-01T00:00:00Z\n")
			}))
			config := DefaultConfig()
			config.SecurityTXT, config.TimeoutMS = true, 200
			started := time.Now()
			observation, failures := testCollector(server, roots, nil).Collect(context.Background(), "https://company.com/", config, "scan")
			if len(failures) != 1 || requests.Load() != 2 || time.Since(started) > 2*time.Second {
				t.Fatalf("phase deadline: %+v requests=%d", failures, requests.Load())
			}
			if timeoutPath == "/" {
				if observation.HTTP != nil || observation.SecurityTXT.Status != "present" || failures[0].Code != "ETIMEDOUT" {
					t.Fatalf("base failure lost security.txt: %+v %+v", observation, failures)
				}
			} else if observation.HTTP == nil || observation.SecurityTXT.Status != "error" || failures[0].Code != "SECURITY_TXT_INCOMPLETE" {
				t.Fatalf("body timeout lost base evidence: %+v %+v", observation, failures)
			}
		})
	}
}

func TestSecurityTXTBodyReadHonorsCallerCancellation(t *testing.T) {
	bodyStarted := make(chan struct{})
	server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/security.txt" {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(bodyStarted)
		<-r.Context().Done()
	}))
	config := DefaultConfig()
	config.SecurityTXT = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		observation Observation
		failures    []CheckError
	}
	completed := make(chan result, 1)
	go func() {
		observation, failures := testCollector(server, roots, nil).Collect(ctx, "https://company.com/", config, "scan")
		completed <- result{observation, failures}
	}()
	select {
	case <-bodyStarted:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("security.txt body read did not start")
	}
	select {
	case got := <-completed:
		if got.observation.HTTP == nil || got.observation.SecurityTXT.Status != "error" || len(got.failures) != 1 || got.failures[0].Code != "SECURITY_TXT_INCOMPLETE" {
			t.Fatalf("cancellation lost evidence: %+v %+v", got.observation, got.failures)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller cancellation did not terminate the body read")
	}
}

func TestTLSHostnameAndTrustFailuresRetainDNSEvidence(t *testing.T) {
	for _, mode := range []string{"hostname", "trust"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			host := "company.com"
			if mode == "hostname" {
				host = "other.example"
			}
			server, roots := tlsFixture(t, host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(200) }))
			if mode == "trust" {
				roots = x509.NewCertPool()
			}
			collector := testCollector(server, roots, nil)
			observation, failures := collector.Collect(context.Background(), "https://company.com", DefaultConfig(), "scan")
			if len(failures) != 1 || failures[0].Code != "TLS_CERTIFICATE_INVALID" || requests.Load() != 0 || observation.HTTP != nil || observation.DNS.SPF.Status != "ok" {
				t.Fatalf("TLS evidence/error: %+v %+v", observation, failures)
			}
		})
	}
}

func TestTransportRejectsSocketDestinationMismatch(t *testing.T) {
	var closed atomic.Bool
	client, server := net.Pipe()
	defer server.Close()
	collector := &Collector{Resolver: &fakeResolver{}, DialContext: func(context.Context, string, string) (net.Conn, error) {
		return &trackedConn{Conn: client, closed: &closed}, nil
	}}
	_, failures := collector.Collect(context.Background(), "https://company.com", DefaultConfig(), "scan")
	if len(failures) != 1 || failures[0].Code != "TLS_DESTINATION_MISMATCH" || !closed.Load() {
		t.Fatalf("mismatch: %+v closed=%v", failures, closed.Load())
	}
}

type trackedConn struct {
	net.Conn
	closed *atomic.Bool
}

func (c *trackedConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestHTTPDeadlineAndHeaderSizeBound(t *testing.T) {
	for _, mode := range []string{"deadline", "headers"} {
		t.Run(mode, func(t *testing.T) {
			server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "deadline" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("X-Oversized", strings.Repeat("a", maxHeaderBytes+1))
				w.WriteHeader(200)
			}))
			collector := testCollector(server, roots, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			observation, failures := collector.Collect(ctx, "https://company.com", DefaultConfig(), "scan")
			if len(failures) != 1 || observation.HTTP != nil || observation.DNS.A.Status != "ok" {
				t.Fatalf("unbounded request: %+v %+v", observation, failures)
			}
			if mode == "deadline" && failures[0].Code != "ETIMEDOUT" {
				t.Fatalf("deadline error: %+v", failures)
			}
		})
	}
}

func TestNetworkErrorsDoNotExposeArbitraryInput(t *testing.T) {
	result := safeNetworkError("https://company.com/", errors.New("SECRET_TOKEN\x1b[31m"))
	if result.Code != "NETWORK_ERROR" || strings.Contains(result.Message, "SECRET") {
		t.Fatalf("unsafe error: %+v", result)
	}
}
