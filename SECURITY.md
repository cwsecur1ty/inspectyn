# Security

Report vulnerabilities through [GitHub private reporting](https://github.com/cwsecur1ty/inspectyn/security/advisories/new). Include the affected version, reproduction steps, expected behavior, and impact. Use synthetic evidence where possible and keep credentials or customer data out of public issues.

Security fixes target the latest version on `main`.

## Scope

`inspectyn scan` sends one HTTPS request per configured public endpoint and queries DNS. The opt-in `--security-txt` check adds one same-origin request to `/.well-known/security.txt`, capped at 64 KiB, using the validated address. Connections verify the TLS certificate and hostname. Redirects, private endpoint connections, and arbitrary ports are not supported; listed security.txt links are not followed.

`inspectyn recon` queries DNS for exact names without connecting to their returned addresses. It does not enumerate hosts. DNS records reflect the configured resolver's responses, not independent authoritative-zone verification.

`inspectyn-js review` and `inspectyn-js report` run offline. Imported templates, commands, and payloads are treated as data and never executed. The retained JavaScript `scan` command uses the same explicit public-endpoint boundary.

Reports include target names, selected response headers, DNS policies, certificate details, cookie names and attribute flags, and accepted source labels. Cookie values, raw Set-Cookie headers, security.txt bodies, and contact URIs are not retained. Reports can contain sensitive information; review them before sharing. Neither executable sends telemetry.

## Optional local web interface

The `inspectyn-web` development scaffold binds only to `127.0.0.1`. It is intended for a single local user and has no account authentication or shared-hosting support. Do not expose it through a proxy, tunnel, or port-forwarding service. Host, Origin, and CSRF-token checks protect browser requests; they do not isolate the service from other processes or users on the same machine.

The server launches the explicitly selected native CLI directly, without a shell, for `scan` and `recon`. Its local listener does not enable private-network scans: the CLI still restricts HTTPS checks to validated public endpoints on port 443, and DNS recon queries exact names only.

The ten most recent jobs and their reports stay in memory until eviction or restart. Temporary CLI configuration files are removed after use. The server does not persist reports to disk; browser downloads create local files under the browser's normal controls. Treat the job history and downloaded reports as sensitive. The web scaffold is not included in the published v0.2.0 release.

See [usage](docs/usage.md) for coverage, limits, and exit codes.
