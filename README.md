<div align="center">

<h1>Inspectyn</h1>
<p><strong>TLS, HTTP and DNS checks</strong></p>

[![CI](https://github.com/cwsecur1ty/inspectyn/actions/workflows/ci.yml/badge.svg)](https://github.com/cwsecur1ty/inspectyn/actions/workflows/ci.yml)
[![Go >=1.24](https://img.shields.io/badge/Go-%3E%3D1.24-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<p>
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#options">Options</a> &bull;
  <a href="#evidence-review">Evidence Review</a> &bull;
  <a href="docs/usage.md">Documentation</a>
</p>

</div>

Inspectyn checks TLS certificates, HTTP security headers, and DNS records. It also reviews Nuclei results and matches supplied inventory against CVE records.

The native Go binary handles scanning and DNS recon. The optional JavaScript command handles offline evidence review and saved reports. Scanning does not require Node.js.

## Install

Download a binary from [Releases](https://github.com/cwsecur1ty/inspectyn/releases/latest), or install with Go **1.24 or later**:

```sh
go install github.com/cwsecur1ty/inspectyn/cmd/inspectyn@latest
inspectyn --help
```

To build from source:

```sh
git clone https://github.com/cwsecur1ty/inspectyn.git
cd inspectyn
go build -o inspectyn ./cmd/inspectyn
./inspectyn --help
```

On Windows, use `go build -o inspectyn.exe ./cmd/inspectyn` and run `./inspectyn.exe`. Ensure the Go binary directory is on `PATH` when using `go install`.

## Usage

Look up records for an exact hostname:

```sh
inspectyn recon -u example.com
```

Check an HTTPS endpoint you are authorized to assess:

```sh
inspectyn scan -u https://your-domain.com
```

Read up to 20 targets from a file, one per line:

```sh
inspectyn scan --list targets.txt --concurrency 4 --format json --out scan.json
```

Save a configuration for repeated runs:

```sh
inspectyn init --target https://your-domain.com --out inspectyn.json
inspectyn scan --config inspectyn.json --format html --out scan.html
```

`scan` checks one response per public HTTPS endpoint on port 443. `recon` queries A, AAAA, SPF, DMARC, and MX records for exact names without connecting to the endpoints. Neither command enumerates hosts, crawls, follows redirects, or runs exploits.

## Options

| Option | Description |
| --- | --- |
| `--target`, `-u` | One HTTPS URL; `recon` also accepts a hostname |
| `--list`, `-l` | UTF-8 target file, one entry per line |
| `--config` | JSON configuration instead of `--target` or `--list` |
| `--concurrency` | Concurrent targets, `1–16`; default `4`, with one check per hostname |
| `--timeout-ms` | DNS/HTTPS phase timeout, `1000–30000`; default `10000` |
| `--no-dns` | Skip SPF, DMARC, and MX queries; address resolution still runs |
| `--format` | `text`, `json`, `markdown`, or `html`; default `text` |
| `--out` | Write a new file instead of stdout |
| `--fail-on` | `info`, `low`, `medium`, `high`, `critical`, or `none`; default `high` |
| `--help`, `-h` | Show help |
| `--version`, `-v` | Show version |

Use exactly one of `--target`, `--list`, or `--config` for `scan` and `recon`. `init` accepts `--target` and `--out`. Files written with `--out` are never overwritten.

## Evidence Review

Install the optional JavaScript command from the repository root. It requires Node.js **22.13 or later** and has no npm dependencies:

```sh
npm install --global .
inspectyn-js review http-baseline --input examples/headers.json
```

There is no published npm package. Without installation, use `node bin/inspectyn-js.mjs`. On Windows PowerShell, use `npm.cmd` and `inspectyn-js.cmd` if the script wrappers are blocked.

| Workflow | Input |
| --- | --- |
| `http-baseline` | HTTP observations with response headers |
| `nuclei-review` | Existing HTTP Nuclei results |
| `kev-match` | Nuclei results + supplied KEV catalogue |
| `cve-applicability` | Inventory + supplied CVE Record |

These workflows run offline. They do not execute Nuclei templates or authenticate supplied intelligence. Bundled examples are fictional fixtures. See [review commands and matching limits](docs/usage.md#offline-reviews).

Native scans produce all four report formats directly. To convert a saved JSON report later:

```sh
inspectyn-js report scan.json --format html --out scan.html
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Processing completed and the severity gate passed or was disabled |
| `1` | An actionable finding meets the selected severity threshold |
| `2` | An error, incomplete evidence, or unknown actionable severity prevents a gate decision |

**Observed** and **Not applicable** findings do not trigger the gate. **Not assessable** findings return `2`. Unknown severity is not ranked; an actionable CVE candidate with unknown severity returns `2` when a gate is enabled.

`--fail-on none` disables severity gating, including unknown-severity gating. Errors and incomplete evidence still return `2`. Reports can be saved successfully with exit `1` or `2`. No findings does not establish that an endpoint is secure.

## Documentation

- [Configuration, check coverage, and limits](docs/usage.md#configuration)
- [Offline reviews](docs/usage.md#offline-reviews)
- [Docker](docs/usage.md#docker)
- [Data handling and compatibility](docs/usage.md#data-handling)
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md)

## License

[MIT](LICENSE). Commercial use, modification, and redistribution are permitted under its terms. Assess only endpoints you own or are authorized to test.
