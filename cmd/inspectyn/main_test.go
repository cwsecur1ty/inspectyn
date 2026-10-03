package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

type offlineCollector struct{}

func (offlineCollector) Collect(_ context.Context, target string, _ inspect.Config, _ string) (inspect.Observation, []inspect.CheckError) {
	return inspect.Observation{}, []inspect.CheckError{{Target: target, Code: "TEST_NETWORK_DISABLED", Message: "No collector is configured for this command test."}}
}

func invoke(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runWithCollector(context.Background(), args, &stdout, &stderr, offlineCollector{})
	return code, stdout.String(), stderr.String()
}

func TestHelpVersionAndInvalidFlags(t *testing.T) {
	code, out, errOut := invoke("--version")
	if code != 0 || out != "0.2.0\n" || errOut != "" {
		t.Fatalf("version: %d %q %q", code, out, errOut)
	}
	code, out, _ = invoke("--help")
	if code != 0 || !strings.Contains(out, "inspectyn recon") {
		t.Fatal("missing native help")
	}
	for _, args := range [][]string{{"scan"}, {"bogus"}, {"scan", "--target", "http://example.com"}, {"recon", "--target", "127.1"},
		{"scan", "--target", "https://example.com", "--format", "xml"}, {"scan", "--target", "https://example.com", "--concurrency", "0"},
		{"scan", "--target", "https://example.com", "-u", "https://two.example.com"}, {"scan", "--target", "https://example.com", "--list", "other"},
		{"init", "--concurrency", "4"}, {"scan", "positional"}} {
		code, out, _ = invoke(args...)
		if code != 2 || out != "" {
			t.Fatalf("%v => %d %q", args, code, out)
		}
	}
}

func TestInitDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inspectyn.json")
	code, _, stderr := invoke("init", "--target", "https://EXAMPLE.com", "--out", path)
	if code != 0 {
		t.Fatal(stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("invalid JSON")
	}
	if _, ok := config["concurrency"]; ok {
		t.Fatal("serialized CLI-only concurrency")
	}
	if config["dns"] != true {
		t.Fatal("mail DNS default lost")
	}
	code, _, _ = invoke("init", "--out", path)
	if code != 2 {
		t.Fatal("overwrote configuration")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("configuration changed")
	}
}

func TestConfigRejectsMalformedUnknownAndMissingSchemaWithoutEchoingContents(t *testing.T) {
	for _, content := range []string{"secret=do-not-echo", `{"targets":["https://example.com"]}`, `{"schemaVersion":1,"targets":["https://example.com"],"followRedirects":true}`, `{"schemaVersion":1,"targets":["https://example.com"]} {}`, `{"schemaVersion":1,"targets":["https://example.com"],"dns":null}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := invoke("scan", "--config", path)
		if code != 2 || out != "" || strings.Contains(stderr, "do-not-echo") {
			t.Fatalf("invalid config: %d %q %q", code, out, stderr)
		}
	}
}

func TestExistingOutputRejectedBeforeScanning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	os.WriteFile(path, []byte("keep"), 0600)
	code, _, stderr := invoke("scan", "--target", "https://example.com", "--out", path)
	if code != 2 || !strings.Contains(stderr, "output already exists") {
		t.Fatal("did not reject existing output")
	}
}

func TestListAndInputLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	os.WriteFile(path, []byte(strings.Repeat("https://example.com\n", 21)), 0600)
	code, _, _ := invoke("scan", "--list", path)
	if code != 2 {
		t.Fatal("accepted excessive targets")
	}
	os.WriteFile(path, bytes.Repeat([]byte("x"), 65537), 0600)
	code, _, stderr := invoke("scan", "--list", path)
	if code != 2 || !strings.Contains(stderr, "size limit") {
		t.Fatal("accepted oversized input")
	}
	if _, err := readFile(filepath.Dir(path), 65536); err == nil {
		t.Fatal("accepted directory")
	}
}
