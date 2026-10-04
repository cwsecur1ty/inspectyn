package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

const help = `Inspectyn - TLS, HTTP and DNS checks

Usage:
  inspectyn scan --target https://example.com
  inspectyn recon --target example.com
  inspectyn scan --target https://example.com --dns-details --security-txt
  inspectyn scan --list targets.txt --concurrency 4 --format json
  inspectyn scan --config inspectyn.json --out report.json --format json
  inspectyn init [--target https://example.com] [--out inspectyn.json]

Options:
  --target, -u     One HTTPS URL; recon also accepts a hostname
  --list, -l       UTF-8 file, one target per line (maximum 20)
  --config        JSON configuration; use instead of --target or --list
  --concurrency   Concurrent targets, 1-16 (default 4; one per hostname)
  --timeout-ms    DNS and HTTPS phase deadline, 1000-30000 (default 10000)
  --no-dns        Skip SPF, DMARC and MX queries; address lookups still run
  --dns-details   Also query NS and the resolver's canonical name
  --security-txt  Check /.well-known/security.txt (scan only; one extra GET)
  --format        text, json, markdown or html (default text)
  --out           Write a new file instead of stdout
  --fail-on       info, low, medium, high, critical or none (default high)
  --help, -h      Show help
  --version, -v   Show version

scan: one HTTPS request per public endpoint, plus optional security.txt.
TLS and cookie attributes come from the endpoint response; no redirects.
recon: DNS records for exact names; no endpoint requests or enumeration.
Exit codes: 0 below threshold, 1 threshold reached, 2 error or incomplete.
Offline evidence review and saved reports: inspectyn-js review / report.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func message(err error) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return ' '
		}
		return r
	}, err.Error())
}

func readFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if info.Size() > limit {
		return nil, errors.New("input exceeds the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("input exceeds the size limit")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("input must be UTF-8")
	}
	return bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), nil
}

func writeFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithCollector(ctx, args, stdout, stderr, nil)
}

func runWithCollector(ctx context.Context, args []string, stdout, stderr io.Writer, collector inspect.TargetCollector) int {
	errOut := func(err error) int { fmt.Fprintln(stderr, "inspectyn:", message(err)); return 2 }
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(stdout, help)
		return 0
	}
	if args[0] == "--version" || args[0] == "-v" {
		fmt.Fprintln(stdout, inspect.Version)
		return 0
	}
	command := args[0]
	if command != "init" && command != "scan" && command != "recon" {
		return errOut(errors.New("unknown command; use inspectyn --help"))
	}
	options := flag.NewFlagSet(command, flag.ContinueOnError)
	options.SetOutput(io.Discard)
	var target, listPath, configPath, format, outPath, failOn string
	var concurrency, timeoutMS int
	var noDNS, dnsDetails, securityTXT, showHelp bool
	options.StringVar(&target, "target", "", "target")
	options.StringVar(&target, "u", "", "target")
	options.StringVar(&outPath, "out", "", "output file")
	options.BoolVar(&showHelp, "help", false, "help")
	options.BoolVar(&showHelp, "h", false, "help")
	if command != "init" {
		options.StringVar(&listPath, "list", "", "target list")
		options.StringVar(&listPath, "l", "", "target list")
		options.StringVar(&configPath, "config", "", "configuration")
		options.StringVar(&format, "format", "text", "report format")
		options.StringVar(&failOn, "fail-on", "high", "severity threshold")
		options.IntVar(&concurrency, "concurrency", 4, "concurrent targets")
		options.IntVar(&timeoutMS, "timeout-ms", 10000, "phase timeout")
		options.BoolVar(&noDNS, "no-dns", false, "skip mail records")
		options.BoolVar(&dnsDetails, "dns-details", false, "query NS and canonical name")
		options.BoolVar(&securityTXT, "security-txt", false, "check security.txt")
	}
	// Duplicate aliases can silently replace the intended target with flag.Parse.
	seen := map[string]bool{}
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if name == "u" {
			name = "target"
		}
		if name == "l" {
			name = "list"
		}
		if name == "h" {
			name = "help"
		}
		if seen[name] {
			return errOut(fmt.Errorf("--%s may only be supplied once", name))
		}
		seen[name] = true
	}
	if err := options.Parse(args[1:]); err != nil {
		return errOut(err)
	}
	if showHelp {
		fmt.Fprint(stdout, help)
		return 0
	}
	if options.NArg() != 0 {
		return errOut(errors.New("unexpected positional argument"))
	}
	config := inspect.DefaultConfig()
	if command == "init" {
		config.Targets = []string{}
		if target != "" {
			normalized, err := inspect.NormalizeTarget(target)
			if err != nil {
				return errOut(err)
			}
			config.Targets = []string{normalized}
		}
		if outPath == "" {
			outPath = "inspectyn.json"
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		if err := writeFile(outPath, append(data, '\n')); err != nil {
			return errOut(err)
		}
		fmt.Fprintln(stdout, "Configuration written.")
		return 0
	}
	inputs := 0
	for _, path := range []string{target, listPath, configPath} {
		if path != "" {
			inputs++
		}
	}
	if inputs != 1 {
		return errOut(errors.New("use exactly one of --target, --list or --config"))
	}
	if !oneOf(format, "text", "json", "markdown", "html") {
		return errOut(errors.New("format must be text, json, markdown or html"))
	}
	if !oneOf(failOn, "info", "low", "medium", "high", "critical", "none") {
		return errOut(errors.New("unknown fail-on severity"))
	}
	if configPath != "" {
		data, err := readFile(configPath, 65536)
		if err != nil {
			return errOut(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&config) != nil {
			return errOut(errors.New("invalid configuration JSON or unknown field"))
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return errOut(errors.New("configuration must contain one JSON object"))
		}
		// The schema must be present even though other omitted values use defaults.
		var supplied map[string]json.RawMessage
		if json.Unmarshal(data, &supplied) != nil || string(bytes.TrimSpace(supplied["schemaVersion"])) != "1" {
			return errOut(errors.New("configuration schemaVersion must be 1"))
		}
		for _, raw := range supplied {
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return errOut(errors.New("configuration fields cannot be null"))
			}
		}
	} else if listPath != "" {
		data, err := readFile(listPath, 65536)
		if err != nil {
			return errOut(err)
		}
		config.Targets = []string{}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				config.Targets = append(config.Targets, line)
			}
		}
	} else {
		config.Targets = []string{target}
	}
	config.Concurrency = concurrency
	if seen["timeout-ms"] {
		config.TimeoutMS = timeoutMS
	}
	if noDNS {
		config.DNS = false
	}
	if seen["dns-details"] {
		config.DNSDetails = dnsDetails
	}
	if seen["security-txt"] {
		config.SecurityTXT = securityTXT
	}
	if outPath != "" {
		if _, err := os.Lstat(outPath); err == nil {
			return errOut(errors.New("output already exists"))
		} else if !os.IsNotExist(err) {
			return errOut(err)
		}
	}
	report, err := inspect.Run(ctx, command, config, collector)
	if err != nil {
		return errOut(err)
	}
	data, err := inspect.RenderReport(report, format)
	if err != nil {
		return errOut(err)
	}
	if outPath != "" {
		err = writeFile(outPath, data)
	} else {
		_, err = stdout.Write(data)
	}
	if err != nil {
		return errOut(err)
	}
	code, err := inspect.ReportExitCode(report, failOn)
	if err != nil {
		return errOut(err)
	}
	return code
}

func oneOf(value string, allowed ...string) bool {
	for _, option := range allowed {
		if value == option {
			return true
		}
	}
	return false
}
