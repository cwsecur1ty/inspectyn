# Local web interface

`inspectyn-web` runs native Inspectyn checks from a local browser interface. It embeds HTML, CSS, and JavaScript in a separate Go executable and starts the `inspectyn` CLI as a subprocess. It needs no frontend build step or Node.js runtime.

The web interface and expanded observations are part of the unreleased `0.3.0-dev` source. They are not included in the published v0.2.0 release.

## Build and run

From the repository root, with Go **1.24 or later**:

```sh
go build -o inspectyn ./cmd/inspectyn
go build -o inspectyn-web ./cmd/inspectyn-web
./inspectyn-web --cli ./inspectyn --port 8788
```

On Windows PowerShell:

```powershell
go build -o inspectyn.exe ./cmd/inspectyn
go build -o inspectyn-web.exe ./cmd/inspectyn-web
./inspectyn-web.exe --cli ./inspectyn.exe --port 8788
```

Open the URL printed by the server, normally `http://127.0.0.1:8788/`. Use `--port 0` to choose an available local port and open the printed URL. The listener remains on `127.0.0.1`; there is no option to bind to a public interface. Stop the server with Ctrl+C.

`--cli` selects the executable used for jobs. Choose the native binary you built and trust; the server runs it directly without a shell. The CLI and web executable must report the same version. Build both from the same source revision.

## Run checks and download reports

Choose `scan` or `recon`, enter up to 20 explicit targets, and set timeout, concurrency, DNS, and severity-gate options. The CLI validates scope and executes the checks:

- `scan` accepts public HTTPS endpoints on port 443. It validates and pins the destination address, verifies TLS, and does not follow redirects.
- `recon` looks up DNS records for exact names without connecting to their returned addresses. It does not enumerate subdomains.

Scans record TLS certificate and connection details, selected response headers, and cookie attributes from the existing endpoint response. Cookie values and raw `Set-Cookie` headers are not retained. Certificate names are recorded as evidence; they are not added to the target list.

Two options add checks:

| Run option | Behavior |
| --- | --- |
| DNS details (NS and canonical name) | Queries NS records and the canonical name for each exact hostname. Available for scan and recon. Off by default. |
| Check security.txt (one extra request) | Fetches `https://<target-host>/.well-known/security.txt` during a scan, with a 64 KiB body limit and no redirects. Off by default; unavailable in recon. |

The SPF, DMARC, and MX option is independent of DNS details. DNS results come from the machine's configured resolver and do not establish authoritative DNS state. The security.txt observation records status, field counts, expiry, canonical matching, and parsing issues; it does not verify a signature or retain contact values or the response body.

The local browser interface does not permit scanning private or internal endpoints. Assess only targets you own or are authorized to test.

One job can run at a time. Cancel interrupts the active CLI process. The interface retains the ten most recent jobs in memory; older jobs are evicted, and restarting the server clears the history. Incomplete or cancelled jobs must not be treated as passing assessments.

Completed report data can be viewed or downloaded as JSON, HTML, Markdown, or text. Downloads preserve the observation metadata without making another request to the targets. A severity-gate result of `1` or `2` can still include a useful report; see [exit codes](../README.md#exit-codes). Review findings and errors alongside the exit code.

The server removes temporary CLI configuration files after use and does not persist reports to disk. Downloading a report creates a file through the browser. Reports can contain target names, response policies, DNS records, and other sensitive evidence; review them before sharing.

## Local boundary and current scope

Requests are checked for valid input, the expected Host and Origin, and a session CSRF token where required. These protections complement the fixed loopback listener. They are not user authentication and do not protect against other local processes that can access the service.

This version supports native `scan` and `recon` jobs. Offline JavaScript evidence reviews, saved-report imports, user accounts, and shared or hosted access are outside the web interface's scope. Use `inspectyn-js` for [offline reviews and saved reports](usage.md#offline-reviews).

Do not expose the interface through a reverse proxy, tunnel, or port forwarding. See [security reporting and data handling](../SECURITY.md#optional-local-web-interface).

## Development checks

The JSON request to `POST /api/jobs` uses `kind`, `targets`, `dns`, `dnsDetails`, `securityTxt`, `timeoutMs`, `concurrency`, and `failOn`. The new booleans default to false when omitted. `securityTxt: true` with `kind: "recon"` is rejected before execution. Check options pass through the temporary CLI configuration; targets never become shell arguments.

The web runner strictly decodes CLI reports, checks target and security.txt URL scope, and verifies the report's exit code and coverage metadata. Complete reports must include explicitly requested DNS details and security.txt results; incomplete runs can retain evidence from the phases that finished. Downloads use the shared native report renderer.

```sh
go test ./...
go vet ./...
```

The regular test suite uses controlled inputs and subprocess fixtures. It should not contact third-party scan targets. Web changes need coverage for request validation, browser request protections, subprocess execution, cancellation, report output, and job retention.
