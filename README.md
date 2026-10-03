<div align="center">

<h1>Spectyn</h1>
<p><strong>Endpoint security checks and evidence review</strong></p>

[![CI](https://github.com/cwsecur1ty/spectyn/actions/workflows/ci.yml/badge.svg)](https://github.com/cwsecur1ty/spectyn/actions/workflows/ci.yml)
[![Node.js >=22.13](https://img.shields.io/badge/Node.js-%3E%3D22.13-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<p>
  <a href="#features">Features</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#commands">Commands</a> &bull;
  <a href="docs/usage.md">Documentation</a>
</p>

</div>

Spectyn checks public HTTPS endpoints and turns existing security evidence into reports. Run it from a terminal, in CI, or in Docker. No account, API key, or npm dependencies required.

## Features

- **Endpoint checks** for TLS certificates, HSTS, CSP, content-type protection, and framing policies.
- **DNS observations** for SPF, DMARC, and MX at the target hostname.
- **Nuclei result review** with grouped findings, reported severity, CVE IDs, and observation dates.
- **KEV matching** against a supplied catalogue and **CVE applicability** checks against supplied inventory.
- **Text, JSON, Markdown, and HTML reports** with evidence, remediation, and source context.
- **CI exit codes** for severity thresholds, errors, and incomplete evidence.

## Installation

Requires Node.js **22.13 or later**. Install from source:

```sh
git clone https://github.com/cwsecur1ty/spectyn.git
cd spectyn
npm install --global .
spectyn --help
```

There is no published npm package. To run without installation:

```sh
node bin/spectyn.mjs --help
```

On Windows PowerShell, use `npm.cmd` and `spectyn.cmd` if the execution policy blocks their script wrappers.

## Quick Start

Review the bundled HTTP evidence and create a report without making network requests:

```sh
spectyn review http-baseline --input examples/headers.json --format json --out report.json
spectyn report report.json --format html --out report.html
```

Check an endpoint you are authorized to assess. Replace the URL with your own:

```sh
spectyn scan --target https://your-domain.com --format text
```

For repeated runs, save your targets in a configuration file:

```sh
spectyn init --target https://your-domain.com --out spectyn.json
spectyn scan --config spectyn.json --format json --out scan.json
```

`init` only writes configuration. `scan` requests the explicit URLs; it does not follow redirects, discover hosts, crawl pages, scan other ports, or run exploits. Only public HTTPS hosts on port 443 are supported.

## Commands

| Command | Purpose |
| --- | --- |
| `spectyn init` | Create a JSON configuration file |
| `spectyn scan` | Check explicit HTTPS endpoints and their DNS records |
| `spectyn review <workflow>` | Review local evidence files offline |
| `spectyn report <report.json>` | Render an existing Spectyn report offline |

| Option | Used by | Description |
| --- | --- | --- |
| `--target <url>` | `init`, `scan` | One explicit HTTPS URL |
| `--config <file>` | `scan` | Configuration with up to 20 targets; use instead of `--target` |
| `--input <file>` | `review` | Evidence JSON or JSONL |
| `--catalog <file>` | `review kev-match` | KEV catalogue JSON |
| `--advisory <file>` | `review cve-applicability` | Published CVE Record JSON |
| `--format <format>` | `scan`, `review`, `report` | `text`, `json`, `markdown`, or `html`; default `text` |
| `--out <file>` | All commands | Write a new file; reports default to stdout |
| `--fail-on <level>` | `scan`, `review`, `report` | `info`, `low`, `medium`, `high`, `critical`, or `none`; default `high` |
| `--help`, `-h` | All commands | Show help |
| `--version`, `-v` | All commands | Show version |

Output files are never overwritten. Choose a new filename for each run.

## Evidence Workflows

| Workflow | Inputs | Result |
| --- | --- | --- |
| `http-baseline` | HTTP observations with response headers | HSTS, CSP, and content-type checks |
| `nuclei-review` | Existing HTTP Nuclei results | Grouped observations and review candidates |
| `kev-match` | Nuclei results + KEV catalogue | Exact CVE-ID matches with catalogue context |
| `cve-applicability` | Inventory + CVE Record | Exact-version candidates and unresolved comparisons |

Spectyn does not execute Nuclei templates or authenticate supplied intelligence. Example files are fictional fixtures. See the [usage guide](docs/usage.md#offline-reviews) for commands, input formats, and matching limits.

## Reports and Exit Codes

Save JSON to retain structured evidence and render other formats later. HTML reports are standalone files with no scripts or external assets.

```sh
spectyn report report.json --format markdown --out report.md
spectyn report report.json --format text
```

| Code | Meaning |
| --- | --- |
| `0` | Processing completed and the severity gate passed or was disabled |
| `1` | An actionable finding meets the selected severity threshold |
| `2` | An error, incomplete evidence, or unknown actionable severity prevents evaluating the gate |

**Observed** and **Not applicable** findings do not trigger the gate. **Not assessable** findings return `2`. Unknown severity is not assigned a numeric rank: an exact-version CVE candidate with unknown severity returns `2` when a severity gate is enabled.

`--fail-on none` disables severity gating, including unknown-severity gating. Errors and incomplete evidence still return `2`. A report may be saved successfully while the command returns `1` or `2`. No findings is not an assurance that an endpoint is secure.

## Documentation

- [Configuration, check coverage, and limits](docs/usage.md#configuration)
- [Offline reviews and CVE matching](docs/usage.md#offline-reviews)
- [Docker](docs/usage.md#docker)
- [Data handling](docs/usage.md#data-handling)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE). Commercial use, modification, and redistribution are permitted under the license terms. Run live checks only against endpoints you own or are authorized to assess.
