package inspect

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const maxCertificateDNSNames = 64

func boundedCertificateText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "\ufffd")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func observeTLS(state *tls.ConnectionState) *TLSObservation {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return nil
	}
	certificate := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(certificate.Raw)
	result := &TLSObservation{
		Authorized: true, Protocol: tls.VersionName(state.Version),
		ValidTo:             certificate.NotAfter.UTC().Format(time.RFC3339Nano),
		ValidFrom:           certificate.NotBefore.UTC().Format(time.RFC3339Nano),
		Subject:             boundedCertificateText(certificate.Subject.String(), 2048),
		Issuer:              boundedCertificateText(certificate.Issuer.String(), 2048),
		FingerprintSHA256:   hex.EncodeToString(fingerprint[:]),
		SignatureAlgorithm:  certificate.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:  certificate.PublicKeyAlgorithm.String(),
		CipherSuite:         tls.CipherSuiteName(state.CipherSuite),
		NegotiatedProtocol:  boundedCertificateText(state.NegotiatedProtocol, 255),
		VerifiedChainLength: len(state.VerifiedChains[0]),
	}
	if certificate.SerialNumber != nil {
		result.SerialNumber = boundedCertificateText(certificate.SerialNumber.Text(16), 128)
	}
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		result.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		result.PublicKeyBits = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		result.PublicKeyBits = len(key) * 8
	}
	// SANs are evidence from this certificate, never additional scan targets.
	names := certificate.DNSNames
	if len(names) > maxCertificateDNSNames {
		result.DNSNamesTruncated = true
		names = names[:maxCertificateDNSNames]
	}
	result.DNSNames = make([]string, 0, len(names))
	for _, name := range names {
		bounded := boundedCertificateText(name, 253)
		if bounded != name {
			result.DNSNamesTruncated = true
		}
		result.DNSNames = append(result.DNSNames, bounded)
	}
	sort.Strings(result.DNSNames)
	return result
}
