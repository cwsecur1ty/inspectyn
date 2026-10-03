package inspect

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const MaxTargets = 20
const MaxConcurrency = 16

type Config struct {
	SchemaVersion int      `json:"schemaVersion"`
	Targets       []string `json:"targets"`
	DNS           bool     `json:"dns"`
	TimeoutMS     int      `json:"timeoutMs"`
	Concurrency   int      `json:"-"`
}

func DefaultConfig() Config {
	return Config{SchemaVersion: 1, Targets: []string{}, DNS: true, TimeoutMS: 10000, Concurrency: 4}
}

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var numericLabel = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)

func validHostname(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
		allNumeric = allNumeric && numericLabel.MatchString(label)
	}
	return !allNumeric
}

func NormalizeTarget(value string) (string, error) {
	if value == "" || len(value) > 2048 || strings.ContainsRune(value, '\\') || strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", fmt.Errorf("targets must be HTTPS URLs without whitespace or control characters")
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("targets must be complete HTTPS URLs")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(value, "#") || (u.Port() != "" && u.Port() != "443") {
		return "", fmt.Errorf("use HTTPS on port 443 without credentials, query strings or fragments")
	}
	host := strings.ToLower(u.Hostname())
	if !validHostname(host) || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("targets must use fully qualified ASCII DNS hostnames; use punycode for international domains")
	}
	u.Scheme, u.Host = "https", host
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func NormalizeReconTarget(value string) (string, error) {
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	target, err := NormalizeTarget(value)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(target)
	if u.EscapedPath() != "/" {
		return "", fmt.Errorf("recon accepts a DNS hostname or HTTPS origin without an endpoint path")
	}
	return target, nil
}

func ValidateConfig(input Config) (Config, error) {
	if input.SchemaVersion != 1 {
		return Config{}, fmt.Errorf("configuration schemaVersion must be 1")
	}
	if len(input.Targets) < 1 || len(input.Targets) > MaxTargets {
		return Config{}, fmt.Errorf("configure between 1 and %d explicit targets", MaxTargets)
	}
	if input.TimeoutMS < 1000 || input.TimeoutMS > 30000 {
		return Config{}, fmt.Errorf("timeoutMs must be between 1000 and 30000")
	}
	if input.Concurrency < 1 || input.Concurrency > MaxConcurrency {
		return Config{}, fmt.Errorf("concurrency must be between 1 and %d", MaxConcurrency)
	}
	targets := make([]string, len(input.Targets))
	seen := make(map[string]bool, len(targets))
	for i, value := range input.Targets {
		target, err := NormalizeTarget(value)
		if err != nil {
			return Config{}, fmt.Errorf("target %d: %w", i+1, err)
		}
		if seen[target] {
			return Config{}, fmt.Errorf("duplicate targets are not allowed")
		}
		seen[target], targets[i] = true, target
	}
	input.Targets = targets
	return input, nil
}
