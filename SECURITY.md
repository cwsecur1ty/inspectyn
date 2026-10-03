# Security

Report vulnerabilities through [GitHub private reporting](https://github.com/cwsecur1ty/inspectyn/security/advisories/new). Include the affected version, reproduction steps, expected behavior, and impact. Use synthetic evidence where possible and keep credentials or customer data out of public issues.

Security fixes target the latest version on `main`.

## Scope

`inspectyn scan` sends one HTTPS request per configured public endpoint and queries DNS. It pins the connection to a validated address and verifies the TLS certificate and hostname. Redirects, private endpoint connections, and arbitrary ports are not supported.

`inspectyn recon` queries DNS for exact names without connecting to their returned addresses. It does not enumerate hosts. DNS records reflect the configured resolver's responses, not independent authoritative-zone verification.

`inspectyn-js review` and `inspectyn-js report` run offline. Imported templates, commands, and payloads are treated as data and never executed. The retained JavaScript `scan` command uses the same explicit public-endpoint boundary.

Reports include target names, selected response headers, DNS policies, and accepted source labels. These can contain sensitive information; review reports before sharing them. Neither executable sends telemetry.

See [usage](docs/usage.md) for coverage, limits, and exit codes.
