package inspect

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeTargetScope(t *testing.T) {
	invalid := []string{"http://company.com", "https://user:pass@company.com", "https://company.com?token=secret", "https://company.com?", "https://company.com#", "https://company.com:8443", "https://*.company.com", "https://127.1", "https://2130706433", "https://0x7f.0.0.1", "https://[::1]", "https://localhost", "https://company.com.", "https://company.com\\@evil.com", "https://company.com\n", "https://company.com:", "https://company..com", "https://éxample.com", "https://" + strings.Repeat("a", 64) + ".com"}
	for _, target := range invalid {
		if result, err := NormalizeTarget(target); err == nil {
			t.Errorf("accepted %q as %q", target, result)
		}
	}
	for value, want := range map[string]string{
		"https://COMPANY.com/path": "https://company.com/path", "https://company.com:443": "https://company.com/",
		"https://xn--xample-9ua.com/a%2Fb": "https://xn--xample-9ua.com/a%2Fb",
	} {
		got, err := NormalizeTarget(value)
		if err != nil || got != want {
			t.Errorf("NormalizeTarget(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
}

func TestReconAcceptsOnlyExactHost(t *testing.T) {
	for _, value := range []string{"company.com", "COMPANY.com", "https://company.com", "https://company.com/"} {
		if got, err := NormalizeReconTarget(value); err != nil || got != "https://company.com/" {
			t.Errorf("NormalizeReconTarget(%q) = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"company.com/path", "https://company.com/path", "https://company.com/%2f", "*.company.com", "company.com:8443", "localhost", "company.com?token=value", "127.0.0.1"} {
		if _, err := NormalizeReconTarget(value); err == nil {
			t.Errorf("accepted recon scope %q", value)
		}
	}
}

func TestConfigBoundsAndCanonicalDuplicates(t *testing.T) {
	base := DefaultConfig()
	base.Targets = []string{"https://COMPANY.com"}
	before := append([]string{}, base.Targets...)
	got, err := ValidateConfig(base)
	if err != nil || got.Targets[0] != "https://company.com/" || got.Concurrency != 4 || !got.DNS {
		t.Fatalf("unexpected config: %+v, %v", got, err)
	}
	if !reflect.DeepEqual(base.Targets, before) {
		t.Fatal("validation changed the caller's target slice")
	}
	for name, edit := range map[string]func(*Config){
		"version": func(c *Config) { c.SchemaVersion = 2 }, "empty": func(c *Config) { c.Targets = nil },
		"many":      func(c *Config) { c.Targets = make([]string, MaxTargets+1) },
		"duplicate": func(c *Config) { c.Targets = []string{"https://company.com", "https://COMPANY.com:443/"} },
		"timeout0":  func(c *Config) { c.TimeoutMS = 0 }, "timeoutLarge": func(c *Config) { c.TimeoutMS = 30001 },
		"parallelLarge": func(c *Config) { c.Concurrency = 17 }, "parallelNegative": func(c *Config) { c.Concurrency = -1 },
		"parallelZero": func(c *Config) { c.Concurrency = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			edit(&config)
			if _, err := ValidateConfig(config); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
