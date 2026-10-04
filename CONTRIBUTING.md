# Contributing

Use Go 1.24 or later for the native CLI. The optional JavaScript tools require Node.js 22.13 or later and have no npm dependencies.

```sh
go test ./...
go vet ./...
go build -o inspectyn ./cmd/inspectyn
npm test
npm pack --dry-run --json
```

On Windows, use `-o inspectyn.exe` and `npm.cmd` if PowerShell blocks the npm wrapper.

The optional local web scaffold is a separate standard-library Go command with embedded HTML, CSS, and JavaScript. Build it with `go build -o inspectyn-web ./cmd/inspectyn-web` (`inspectyn-web.exe` on Windows). The existing `go test ./...` and `go vet ./...` commands include its packages. See [web setup](docs/web.md) for running it with a locally built CLI.

Web changes should test request validation, Host/Origin and CSRF checks, subprocess argument handling, cancellation, job retention, and escaped report display. Keep the listener on loopback and use controlled CLI fixtures in tests; do not run live scans as part of the regular suite.

With `go` on `PATH`, build release archives and SHA-256 checksums for Linux, macOS, and Windows (amd64 and arm64):

```sh
go run ./scripts/build-release.go -out release
```

The output directory must not already exist. Each archive contains the native executable, README, and license.

Keep pull requests focused. Describe the behavior change, include a small example where useful, and add tests for affected checks. Tests should use synthetic evidence, controlled test servers, and injected network responses rather than third-party targets.

Network changes should cover destination validation, TLS verification, concurrency, timeouts, response limits, and redirects. Preserve unknown and incomplete states when evidence is missing or a check fails. Document changes to flags, configuration, report schemas, and exit codes, including compatibility between native reports and the JavaScript renderer.

Keep credentials, customer data, and production scan captures out of fixtures. Explain new dependencies and why the standard library is insufficient. For vulnerability reports, follow [SECURITY.md](SECURITY.md).
