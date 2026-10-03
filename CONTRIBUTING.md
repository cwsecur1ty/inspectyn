# Contributing

Spectyn uses Node.js 22.13 or later and has no npm dependencies. No build step is required.

```sh
node bin/spectyn.mjs --help
npm test
npm pack --dry-run --json
```

Use `npm.cmd` on Windows if PowerShell blocks the npm script wrapper.

Keep pull requests focused. Describe the behavior change, include a small example where useful, and add tests for the affected checks. The test suite runs offline using synthetic evidence and injected network responses.

Changes to network handling should cover destination validation, TLS verification, timeouts, response limits, and redirects. Preserve unknown and incomplete states when evidence is missing or a check cannot finish. Document changes to configuration, report schemas, flags, and exit codes.

Keep credentials, customer data, and real scan captures out of fixtures. For a new dependency, explain what it adds and why the standard library is insufficient.

CI runs the tests on Node 22 and 24 across Linux, Windows, and macOS. For vulnerability reports, follow [SECURITY.md](SECURITY.md).
