package inspect

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type collectorFunc func(context.Context, string, Config, string) (Observation, []CheckError)

func (f collectorFunc) Collect(ctx context.Context, target string, config Config, kind string) (Observation, []CheckError) {
	return f(ctx, target, config, kind)
}

func healthyObservation(target string) Observation {
	u, _ := url.Parse(target)
	return Observation{URL: target, Hostname: u.Hostname(), Addresses: []string{"8.8.8.8"}, ObservedAt: time.Now().UTC().Format(time.RFC3339),
		HTTP: &HTTPObservation{Status: 200, Headers: map[string][]string{"content-type": {"application/json"}, "strict-transport-security": {"max-age=31536000"}, "x-content-type-options": {"nosniff"}}},
		TLS:  &TLSObservation{Authorized: true, Protocol: "TLSv1.3", ValidTo: "2099-01-01T00:00:00Z"}}
}

func TestRunBoundsConcurrencyAndKeepsTargetOrder(t *testing.T) {
	config := DefaultConfig()
	config.Targets = []string{"https://a.example.com/one", "https://b.example.com/", "https://a.example.com/two", "https://c.example.com/", "https://d.example.com/"}
	config.Concurrency = 3
	var mu sync.Mutex
	active, maximum := 0, 0
	hosts := map[string]int{}
	collector := collectorFunc(func(ctx context.Context, target string, _ Config, _ string) (Observation, []CheckError) {
		u, _ := url.Parse(target)
		mu.Lock()
		active++
		hosts[u.Hostname()]++
		maximum = max(maximum, active)
		if hosts[u.Hostname()] > 1 {
			t.Errorf("overlapping requests to %s", u.Hostname())
		}
		mu.Unlock()
		if u.Hostname() == "a.example.com" {
			time.Sleep(30 * time.Millisecond)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
		mu.Lock()
		active--
		hosts[u.Hostname()]--
		mu.Unlock()
		return healthyObservation(target), nil
	})
	report, err := Run(context.Background(), "scan", config, collector)
	if err != nil {
		t.Fatal(err)
	}
	if maximum > 3 || maximum < 2 {
		t.Fatalf("unexpected concurrency %d", maximum)
	}
	if !report.Complete {
		t.Fatalf("unexpected incomplete report: %+v", report)
	}
	for i, ob := range report.Observations {
		if ob.URL != config.Targets[i] {
			t.Fatalf("result order differs at %d", i)
		}
	}
	if len(report.Observations) != len(config.Targets) {
		t.Fatal("missing observations")
	}
}

func TestRunRetainsPartialEvidenceAndCannotPassErrors(t *testing.T) {
	config := DefaultConfig()
	config.Targets = []string{"https://one.example.com", "https://two.example.com"}
	report, err := Run(context.Background(), "scan", config, collectorFunc(func(_ context.Context, target string, _ Config, _ string) (Observation, []CheckError) {
		ob := healthyObservation(target)
		if ob.Hostname == "two.example.com" {
			ob.HTTP = nil
			ob.TLS = nil
			return ob, []CheckError{{Target: target, Code: "TLS_CERTIFICATE_INVALID", Message: "Certificate could not be verified."}}
		}
		return ob, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || len(report.Observations) != 2 || len(report.Errors) != 1 {
		t.Fatalf("lost partial evidence: %+v", report)
	}
	code, err := ReportExitCode(report, "none")
	if err != nil || code != 2 {
		t.Fatalf("failed check passed gate: %d %v", code, err)
	}
}

func TestRunCancellationDoesNotStartTargetRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	config := DefaultConfig()
	config.Targets = []string{"https://one.example.com", "https://two.example.com"}
	report, err := Run(ctx, "scan", config, collectorFunc(func(context.Context, string, Config, string) (Observation, []CheckError) {
		t.Error("collector called after cancellation")
		return Observation{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || len(report.Errors) != 2 {
		t.Fatal("cancellation was not recorded")
	}
	// Run and the collector must report cancellation with the same code.
	if code := safeNetworkError("", context.Canceled).Code; report.Errors[0].Code != code {
		t.Fatalf("cancellation code %q differs from collector code %q", report.Errors[0].Code, code)
	}
}

func TestReconCanonicalizesWithoutMutatingInput(t *testing.T) {
	config := DefaultConfig()
	config.Targets = []string{"example.com"}
	report, err := Run(context.Background(), "recon", config, collectorFunc(func(_ context.Context, target string, _ Config, kind string) (Observation, []CheckError) {
		if kind != "recon" || target != "https://example.com/" {
			t.Fatalf("unexpected target/mode: %s %s", target, kind)
		}
		return Observation{URL: target, Hostname: "example.com", Addresses: []string{}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.Targets[0] != "example.com" || report.Kind != "recon" {
		t.Fatal("mutated input or lost recon kind")
	}
}

func TestExpandedChecksContributeFindingsAndCoverage(t *testing.T) {
	config := DefaultConfig()
	config.Targets = []string{"https://example.com"}
	config.DNSDetails, config.SecurityTXT = true, true
	report, err := Run(context.Background(), "scan", config, collectorFunc(func(_ context.Context, target string, _ Config, _ string) (Observation, []CheckError) {
		ob := healthyObservation(target)
		ob.DNS = &DNSObservation{NS: &DNSResult{Status: "error", Records: []string{}}, CNAME: &DNSResult{Status: "ok", Records: []string{"edge.example.com"}}}
		ob.HTTP.Cookies = &CookieObservation{Status: "ok", Total: 1, Items: []CookieAttributes{{Index: 1, Name: "session", SameSite: "lax"}}}
		return ob, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || report.Context["dnsDetails"] != true || report.Context["securityTxt"] != true {
		t.Fatalf("missing coverage state: %+v", report)
	}
	seenCookie, seenDNS := false, false
	for _, finding := range report.Findings {
		seenCookie = seenCookie || finding.RuleID == "INSPECTYN_COOKIE_SECURE_MISSING"
		seenDNS = seenDNS || (finding.RuleID == "SPECTYN_DNS_CHECK_INCOMPLETE" && strings.Contains(finding.Evidence, "NS"))
	}
	if !seenCookie || !seenDNS {
		t.Fatalf("new checks did not feed report findings: %+v", report.Findings)
	}
	if code, err := ReportExitCode(report, "none"); err != nil || code != 2 {
		t.Fatalf("incomplete DNS details passed the gate: %d %v", code, err)
	}
}
