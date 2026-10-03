# Security

Report vulnerabilities through [GitHub's private reporting form](https://github.com/cwsecur1ty/spectyn/security/advisories/new). Include the affected version, reproduction steps, expected behavior and impact. Use synthetic evidence where possible. Keep credentials and customer data out of public issues.

Security fixes target the latest version on `main`.

## Scope

`review` and `report` run offline. `scan` sends one HTTPS request per configured endpoint and queries DNS. Connections use a validated public IP with TLS and hostname verification. Redirects, private addresses and arbitrary ports are not supported.

Imported templates and payloads are treated as data and never executed. Reports include target names, selected response headers, DNS policies and accepted source labels. These fields may contain sensitive information; review reports before sharing them. The CLI sends no telemetry.

See [usage](docs/usage.md) for limits and exit codes.
