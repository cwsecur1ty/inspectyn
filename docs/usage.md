# Usage

Inspectyn provides two commands:

- `inspectyn`: native Go executable for `scan`, `recon`, and `init`. No Node.js runtime is required.
- `inspectyn-js`: optional Node.js command for offline `review` and saved `report` rendering. Requires Node.js 22.13 or later.

The native 0.3.0 development version adds TLS connection details, cookie attribute checks, `--dns-details`, and `--security-txt`. Build from this source tree to use them; the published v0.2.0 release does not include these additions.

## Configuration

```sh
inspectyn init --target https://your-domain.com --out inspectyn.json
```

`init` writes configuration without making network requests. Omit `--target` to create an empty target list for editing.

```json
{
  "schemaVersion": 1,
  "targets": ["https://your-domain.com/"],
  "dns": true,
  "timeoutMs": 10000
}
```

| Field | Values |
| --- | --- |
| `schemaVersion` | Required; must be `1` |
| `targets` | 1–20 distinct targets |
| `dns` | Defaults to `true`; `false` skips SPF, DMARC, and MX queries |
| `dnsDetails` | Defaults to `false`; `true` also queries NS and the resolver's canonical name |
| `securityTxt` | Defaults to `false`; `true` adds one request for `/.well-known/security.txt`; scan only |
| `timeoutMs` | 1,000–30,000 milliseconds per DNS/HTTPS phase; defaults to 10,000 |

```sh
inspectyn scan --config inspectyn.json --concurrency 4 --format json --out scan.json
```

`--timeout-ms` overrides the configured timeout. `--no-dns` skips mail-policy queries even when `dns` is `true`. Address lookups still run. Concurrency is a command-line option, not a JSON field: it accepts `1–16` and defaults to `4`. Checks for different hosts can run concurrently; checks for the same hostname are serialized.

`--dns-details` and `--security-txt` enable their respective checks. Use `--dns-details=false` or `--security-txt=false` to override an enabled configuration field. DNS details are independent of `--no-dns`. Recon rejects `securityTxt: true`; disable it explicitly when reusing a scan configuration.

### Target files

Use `--list targets.txt` instead of `--target` or `--config`. Files must be UTF-8, with one target per line. Blank lines and lines beginning with `#` are ignored. At most 20 targets are accepted, and the file limit is 64 KiB.

```text
https://your-domain.com/
https://api.your-domain.com/health
```

For DNS recon, entries can be hostnames or HTTPS origins without paths:

```sh
inspectyn recon --list domains.txt --concurrency 4 --format json --out dns.json
```

### HTTPS scanning

```sh
inspectyn scan -u https://your-domain.com --format text
```

Scan targets must be HTTPS URLs on port 443 with fully qualified ASCII DNS hostnames. Use punycode for international domain names. IP literals, wildcards, credentials, query strings, and fragments are rejected. Endpoint paths are supported.

For each target, Inspectyn resolves its addresses, checks that every returned address is public, and pins one HTTPS connection to a selected address. It verifies the certificate and hostname, reads one response, then closes the connection without analyzing the body. It does not follow redirects. Response headers are capped at 32 KiB. Timeouts apply per DNS/HTTPS phase, not to the entire scan.

The verified connection supplies the leaf certificate's subject, issuer, validity dates, DNS names, serial number, SHA-256 fingerprint, signature and key algorithms, key size where available, negotiated TLS version and cipher suite, ALPN, and verified chain length. At most 64 DNS names are retained; truncation is marked. This describes the negotiated connection, not every TLS version or cipher the server supports.

Cookie checks inspect `Set-Cookie` headers on the returned response, including redirects and error responses. Reports retain names and flags for Secure, HttpOnly, SameSite, Domain presence, root Path, and Partitioned. They omit cookie values and raw headers. At most 64 cookies are assessed; malformed or ambiguous attributes leave the assessment incomplete. Missing flags are review prompts: Inspectyn does not know whether a cookie carries authentication state or needs JavaScript access.

### security.txt

```sh
inspectyn scan -u https://your-domain.com --security-txt
```

This opt-in check sends one extra GET to the same origin's `/.well-known/security.txt`, using the already validated address and a separate HTTPS phase deadline. It does not follow redirects, try a root-path fallback, or contact any listed URI. The body is limited to 64 KiB.

Checks cover status, UTF-8 plain text, Contact presence and URI syntax, one parseable Expires field, expiry, and whether a supplied Canonical field includes the requested URL. Missing files are informational review items. Redirects, unsupported responses, nonmatching Canonical fields, and clear-signed files leave the assessment unresolved. OpenPGP signatures and contact channels are not verified; this is a subset of [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html), not a full compliance check. Reports retain the request URL, status, contact count, expiry, canonical flags, and issue codes, not the body or contact URIs.

### DNS recon

```sh
inspectyn recon -u example.com
```

Recon queries A, AAAA, SPF, DMARC, and MX records for the exact configured names. It does not connect to any returned address, enumerate subdomains, or request an HTTPS endpoint. `--no-dns` skips the three mail-record queries.

Use `--dns-details` to also query NS and the resolver's canonical name. The `cname` observation is the final canonical name supplied by the resolver, not a raw CNAME record set or a complete alias chain. An unchanged canonical name is represented by an empty record list. An absent NS answer at a service hostname does not establish whether the parent zone has name servers. Returned names are never added as targets.

DNS observations come from the machine's configured resolver. They are not independent authoritative-zone verification. A lookup failure is distinct from an absent record and leaves the report incomplete.

### Check coverage

| Area | Coverage |
| --- | --- |
| TLS | Certificate verification, hostname match, expiry, leaf certificate and negotiated connection details |
| HTTP | HSTS, content-type protection, CSP presence, and selected framing-policy checks |
| Cookies | Attribute metadata and selected Secure, HttpOnly, SameSite and prefix checks; no values retained |
| security.txt | Optional bounded request; selected format, required-field, expiry and Canonical checks |
| A/AAAA | Addresses returned for the configured hostname |
| SPF | Direct record presence, duplicates, and selected syntax/fallback checks |
| DMARC | Direct record presence, duplicates, and selected policy checks |
| MX | Records returned for the configured hostname |
| NS / canonical name | Optional resolver queries for the exact configured hostname; no enumeration |

SPF is queried at the exact target hostname; DMARC at `_dmarc.<hostname>`. Parent-domain DMARC inheritance and recursive SPF mechanisms are not evaluated. A missing direct record does not establish the effective mail policy or whether a hostname sends mail.

Header presence does not establish policy strength. HTTP checks describe the returned response, including error pages and redirects. Inspectyn does not crawl, discover hosts, scan other ports, authenticate to applications, connect to private endpoints, or execute exploits.

## Offline reviews

Install the JavaScript command from the repository root:

```sh
npm install --global .
```

There is no published npm package. Without global installation, replace `inspectyn-js` with `node bin/inspectyn-js.mjs`. All review commands below read local files and make no network requests.

### HTTP baseline

```sh
inspectyn-js review http-baseline --input examples/headers.json
```

Accepts JSON observations with `url`, `headers`, and optional `observedAt`. Headers can be an object or an array of `{ "name": "...", "value": "..." }` entries. Checks cover HSTS, enforced CSP on HTML responses, and `X-Content-Type-Options`. Missing scheme or response context can leave a check **Not assessable**. Report-only CSP does not count as enforcement.

### Nuclei results

```sh
inspectyn-js review nuclei-review --input examples/nuclei.json --fail-on none
```

Accepts HTTP Nuclei JSON objects, arrays, or JSONL. Negative matcher events and errors are counted and excluded. Positive observations are grouped by template, service origin, matcher, CVE IDs, and reported severity. Counts and first/latest supplied dates remain in the report. Imported matches are review candidates; no template is executed.

### KEV matching

```sh
inspectyn-js review kev-match --input examples/nuclei.json --catalog examples/kev.json --fail-on none
```

Matches exact CVE IDs against the supplied catalogue's `vulnerabilities` array and retains `catalogVersion` and `dateReleased`. A nonmatch means the ID was absent from that snapshot. Findings without a CVE ID retain unknown KEV status. The catalogue is not downloaded or authenticated.

### CVE applicability

```sh
inspectyn-js review cve-applicability --input examples/inventory.json --advisory examples/advisory.json --fail-on none
```

Inventory rows supply `asset`, `vendor`, `product`, `version`, `source`, and `observedAt`. The advisory must be a published CVE Record in format 5.0, 5.1, or 5.2.

The comparison uses case-insensitive exact vendor/product identity and explicit exact-version CNA entries. An affected entry produces **Needs review**. An unaffected entry applies only to that advisory and observation. Version ranges, platform/module qualifiers, transitions, conflicts, and incomplete inventory remain **Not assessable**. Default status and ADP entries are not used to infer applicability.

CVE candidates have unknown severity. An enabled severity gate therefore returns `2` for actionable candidates. `--fail-on none` disables that gate but still returns `2` for incomplete evidence or errors. A candidate does not establish exploitability.

### Input limits

| Input | Limit |
| --- | --- |
| Evidence or CVE Record | 2 MiB |
| Evidence observations | 500 per review |
| KEV catalogue | 8 MiB and 20,000 entries |
| Saved report | 10 MiB |
| Configuration or target list | 64 KiB |

Inputs must be regular UTF-8 files; stdin and named pipes are not accepted. Supplied evidence and intelligence are not authenticated. Files in `examples/` are fictional fixtures, including examples that use a real CVE ID to demonstrate matching. Fixture files are not automatically identified by the CLI.

## Reports

Native `scan` and `recon`, and JavaScript `review` and `report`, support `--format text|json|markdown|html`, `--out`, and `--fail-on`. Defaults are text on stdout and a `high` severity threshold.

```sh
inspectyn scan -u https://your-domain.com --format json --out scan.json
inspectyn-js report scan.json --format html --out scan.html
inspectyn-js report scan.json --format markdown --out scan.md
```

Save JSON to render another format later. `inspectyn-js report` validates the saved schema and reapplies the selected exit gate. HTML reports contain their own styling without scripts or external assets. `--out` exclusively creates a file and refuses to overwrite an existing path.

Exit `0` means completed processing with a passed or disabled gate. Exit `1` means an actionable finding meets the threshold. Exit `2` means invalid input, an error, incomplete evidence, or unknown actionable severity with a gate enabled. **Observed** and **Not applicable** findings do not trigger severity gates; **Not assessable** findings return `2` even with `--fail-on none`.

The report's `complete` field describes evidence processing separately from severity gating. A complete report can have an unknown-severity candidate that prevents a threshold decision. Reports can still be saved when a command returns `1` or `2`.

## Docker

Build the native image from the repository root:

```sh
docker build -t inspectyn .
docker run --rm inspectyn --help
docker run --rm inspectyn recon -u example.com --format json > dns.json
docker run --rm inspectyn scan -u https://your-domain.com --format json > scan.json
```

The native image contains the Go binary and runs as UID `65532`; Node.js is not included. It uses a scratch runtime with a CA bundle for TLS verification.

Build the separate image for offline reviews:

```sh
docker build -f Dockerfile.review -t inspectyn-review .
docker run --rm --network none inspectyn-review review http-baseline --input /opt/inspectyn/examples/headers.json --format json > report.json
```

Mount your working directory read-only to review your own evidence:

```sh
docker run --rm --network none --mount "type=bind,source=${PWD},target=/work,readonly" inspectyn-review review http-baseline --input headers.json --format html > report.html
```

The review image uses Node.js and runs as the non-root `node` user. Both images write to stdout in these examples, so the containers need no write access to mounted files. Host shell redirection can overwrite files; exclusive output protection applies only to `--out`.

On Windows PowerShell 5.1, use `| Out-File -Encoding utf8 report.json` instead of `> report.json` to save UTF-8 JSON.

## Data handling

Inspectyn has no telemetry or hosted storage. Offline reviews stay on the machine running them. Live scans contact the configured endpoint and DNS resolver. DNS recon contacts the resolver without connecting to the named endpoints.

Normalized reviews exclude raw request/response bodies, replay commands, complete templates, and URL credentials, paths, and queries. Accepted titles and source labels remain supplied text. Scan and recon reports retain target names, selected headers, DNS observations, certificate metadata, cookie names and attribute flags, and security.txt assessment metadata when requested. Cookie values, raw Set-Cookie headers, security.txt bodies, and contact URIs are not retained. Apply appropriate access controls to reports before sharing them.

### Compatibility

`inspectyn-js report` reads schema-version-1 reports from Inspectyn and the former Spectyn name, including native `scan` and `recon` reports. Historical `SPECTYN_` and `spectyn.*` rule IDs and the `spectyn-evidence/1.0` ruleset remain stable. Existing report provenance is preserved.

The JavaScript `init` and `scan` commands remain available as `inspectyn-js init` and `inspectyn-js scan`. They keep the earlier sequential implementation and do not accept the native `--list`, `--concurrency`, `--dns-details`, `--security-txt`, or `recon` interface. Saved native reports retain their added metadata when rendered by `inspectyn-js report`.

Results cover only the supplied evidence and requested checks. No findings does not establish that a target is secure.
