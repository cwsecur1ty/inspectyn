# Usage

Commands below use the installed `spectyn` command. Without a global installation, replace it with `node bin/spectyn.mjs` from the repository root.

## Configuration

Create a configuration file:

```sh
spectyn init --target https://your-domain.com --out spectyn.json
```

`init` makes no network requests. Running it without `--target` creates an empty target list to edit before scanning.

```json
{
  "schemaVersion": 1,
  "targets": ["https://your-domain.com/"],
  "dns": true,
  "timeoutMs": 10000
}
```

| Field | Accepted values |
| --- | --- |
| `schemaVersion` | `1` |
| `targets` | 1–20 distinct public HTTPS URLs on port 443 |
| `dns` | `true` by default; `false` skips mail-policy queries |
| `timeoutMs` | 1,000–30,000 milliseconds per DNS/HTTPS phase; default 10,000 |

Targets require fully qualified DNS hostnames. IP literals, wildcards, credentials, query strings, and fragments are rejected. URL paths are supported. DNS address resolution is still required when `dns` is `false`.

```sh
spectyn scan --config spectyn.json --format json --out scan.json
```

Targets are processed sequentially. For each target, Spectyn resolves its addresses, checks that every returned address is public, and pins one HTTPS connection to a selected address. It verifies the TLS certificate and hostname, reads one response, and closes the connection without analyzing the body. Redirects are reported but not followed. The header limit is 32 KiB. Timeouts apply to individual phases, not to the entire scan.

### Check coverage

| Area | Coverage |
| --- | --- |
| TLS | Certificate verification, hostname match, and expiry |
| HTTP | HSTS, selected content-type protections, CSP presence, and framing-policy observations |
| SPF | Direct record presence, duplicate records, and selected syntax/fallback checks |
| DMARC | Direct record presence, duplicate records, and selected policy checks |
| MX | Records observed at the target hostname |

SPF is queried at the exact target hostname. DMARC is queried at `_dmarc.<target hostname>`. Parent-domain DMARC inheritance and recursive SPF mechanisms are not evaluated. A missing direct record does not establish the effective mail policy or whether the host sends mail.

Header presence does not establish policy strength. Checks describe the returned response, which may be an error page or redirect. Spectyn does not crawl, discover subdomains, scan other ports, authenticate to applications, inspect private endpoints, or execute exploits.

## Offline reviews

All review commands read local UTF-8 files and make no network requests.

### HTTP baseline

```sh
spectyn review http-baseline --input examples/headers.json
```

Accepts JSON observations with `url`, `headers`, and optional `observedAt`. Headers can be an object or an array of `{ "name": "...", "value": "..." }` entries. Checks cover HSTS, enforced CSP on HTML responses, and `X-Content-Type-Options`. Missing scheme or response context can leave a check **Not assessable**. Report-only CSP does not count as enforcement.

### Nuclei results

```sh
spectyn review nuclei-review --input examples/nuclei.json --fail-on none
```

Accepts an HTTP Nuclei JSON object, array, or JSONL file. Negative matcher events and error events are counted and excluded. Positive observations are grouped by template, service origin, matcher, CVE IDs, and reported severity. Counts and first/latest supplied observation dates remain in the report.

This command imports results; it does not run Nuclei or execute templates. An imported match remains a review candidate.

### KEV matching

```sh
spectyn review kev-match --input examples/nuclei.json --catalog examples/kev.json --fail-on none
```

Matches exact CVE IDs against the supplied catalogue's `vulnerabilities` array and preserves `catalogVersion` and `dateReleased`. A nonmatch means the ID was absent from that snapshot. Records with no CVE ID retain unknown KEV status. The CLI does not download or authenticate the catalogue.

### CVE applicability

```sh
spectyn review cve-applicability --input examples/inventory.json --advisory examples/advisory.json --fail-on none
```

Inventory observations supply `asset`, `vendor`, `product`, `version`, `source`, and `observedAt`. The advisory must be one published CVE Record in format 5.0, 5.1, or 5.2.

The comparison uses case-insensitive exact vendor/product identity and explicit exact-version CNA entries. An affected-version match produces **Needs review**. An explicit unaffected entry applies only to that advisory and observation. Version ranges, platform/module qualifiers, transitions, conflicts, and incomplete inventory remain **Not assessable**. Default status and ADP entries are not used to infer applicability.

CVE candidates have unknown severity. With an enabled severity gate, actionable unknown severity returns exit `2`; `--fail-on none` allows a completed review to succeed while retaining those candidates. It does not suppress incomplete evidence or errors. See [exit codes](../README.md#reports-and-exit-codes).

### Input limits and provenance

| Input | Limit |
| --- | --- |
| Evidence or CVE Record | 2 MiB |
| Evidence observations | 500 per review |
| KEV catalogue | 8 MiB and 20,000 entries |
| Saved Spectyn report | 10 MiB |
| Configuration file | 64 KiB |

Inputs must be regular UTF-8 files. Standard input and named pipes are not accepted. Supplied evidence and intelligence are not authenticated. The files in `examples/` are fictional fixtures, including examples that use a real CVE ID to illustrate matching. The CLI does not automatically detect fixture files.

## Reports

`scan`, `review`, and `report` accept `--format text|json|markdown|html`, `--out`, and `--fail-on`. Text on stdout and a `high` severity threshold are the defaults.

```sh
spectyn review http-baseline --input examples/headers.json --format json --out headers.json
spectyn report headers.json --format html --out headers.html
spectyn report headers.json --format markdown --out headers.md
```

Keep JSON when you need to render another format. `report` validates the saved schema and applies the selected exit gate again. HTML includes its own styling with no scripts or external assets. Existing files are never overwritten through `--out`.

The `complete` field records whether evidence processing completed. Severity gating is separate: a completed report can contain an actionable finding whose unknown severity prevents a threshold decision. Review state, errors, source context, dates, and recommendations remain available in the report.

## Docker

Build the image from the repository root:

```sh
docker build -t spectyn .
docker run --rm --network none spectyn review http-baseline --input /opt/spectyn/examples/headers.json --format json > report.json
```

To review your own evidence, mount the working directory read-only:

```sh
docker run --rm --network none --mount "type=bind,source=${PWD},target=/work,readonly" spectyn review http-baseline --input headers.json --format html > report.html
```

Live scans require network access:

```sh
docker run --rm spectyn scan --target https://your-domain.com --format json > scan.json
```

The container runs as the non-root `node` user. These examples send output to the host shell, so the container does not need write access to a mounted directory. Shell redirection can overwrite files; the CLI's exclusive-file protection applies only to `--out`.

On Windows PowerShell 5.1, use `| Out-File -Encoding utf8 report.json` instead of `> report.json` to save UTF-8 JSON.

## Data handling

Spectyn has no telemetry or hosted storage. Offline reviews stay on the machine running the command. Live scans contact the supplied endpoint and DNS resolver.

Normalized review reports exclude raw request/response bodies, replay commands, complete templates, and URL credentials, paths, and queries. Accepted titles, source labels, and other text remain supplied evidence. Live scan reports retain configured target URLs, selected response headers, DNS observations, and certificate metadata. Treat report files according to the sensitivity of their contents.

No findings is not an assurance that a target is secure. Results cover only the supplied evidence and requested checks.
