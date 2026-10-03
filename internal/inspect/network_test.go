package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
			observation, failures := collector.Collect(context.Background(), "https://company.com", DefaultConfig(), "scan")
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

func tlsFixture(t *testing.T, hostname string, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
		w.Header().Set("Set-Cookie", "SECRET_COOKIE")
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
