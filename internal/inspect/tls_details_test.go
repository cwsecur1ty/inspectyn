package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTLSMetadataIsBoundedAndRequiresVerification(t *testing.T) {
	if observeTLS(nil) != nil || observeTLS(&tls.ConnectionState{}) != nil || observeTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}) != nil {
		t.Fatal("unverified TLS state exported as authorized")
	}
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: strings.Repeat("\u754c", 1000)}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(3600, 0)}
	for i := 0; i < 65; i++ {
		certificate.DNSNames = append(certificate.DNSNames, fmt.Sprintf("host%d.example.com", i))
	}
	state := &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, NegotiatedProtocol: "h2", PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate, {}}}}
	result := observeTLS(state)
	if !result.DNSNamesTruncated || len(result.DNSNames) != 64 || len(result.Subject) > 2048 || !utf8.ValidString(result.Subject) || result.NegotiatedProtocol != "h2" || result.CipherSuite != "TLS_AES_128_GCM_SHA256" || result.VerifiedChainLength != 2 {
		t.Fatalf("unbounded or missing TLS details: %+v", result)
	}
	certificate.DNSNames = []string{strings.Repeat("x", 254)}
	result = observeTLS(state)
	if !result.DNSNamesTruncated || len(result.DNSNames[0]) != 253 {
		t.Fatalf("oversized SAN: %+v", result)
	}
}

func TestTLSPublicKeySizes(t *testing.T) {
	for _, scenario := range []struct {
		key       any
		algorithm x509.PublicKeyAlgorithm
		bits      int
	}{
		{&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}, x509.RSA, 2048},
		{&ecdsa.PublicKey{Curve: elliptic.P384()}, x509.ECDSA, 384},
		{make(ed25519.PublicKey, ed25519.PublicKeySize), x509.Ed25519, 256},
	} {
		certificate := &x509.Certificate{PublicKey: scenario.key, PublicKeyAlgorithm: scenario.algorithm}
		result := observeTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}})
		if result.PublicKeyBits != scenario.bits || result.PublicKeyAlgorithm != scenario.algorithm.String() {
			t.Fatalf("key detail: %+v", result)
		}
	}
}

func TestCertificateSANsNeverBecomeTargets(t *testing.T) {
	server, roots := tlsFixture(t, "company.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "company.com" {
			t.Error("certificate SAN was contacted")
		}
		w.WriteHeader(200)
	}), "company.com", "other.example", "*.different.example")
	collector := testCollector(server, roots, nil)
	observation, failures := collector.Collect(context.Background(), "https://company.com/", DefaultConfig(), "scan")
	if len(failures) != 0 || len(observation.TLS.DNSNames) != 3 {
		t.Fatalf("SAN observation: %+v %+v", observation.TLS, failures)
	}
	for _, query := range collector.Resolver.(*fakeResolver).calls {
		if !strings.HasSuffix(query, "company.com") {
			t.Fatalf("SAN expanded DNS scope: %s", query)
		}
	}
}
