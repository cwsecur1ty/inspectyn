import test from 'node:test';
import assert from 'node:assert/strict';
import { renderReport, reportExitCode, validateReport } from '../src/report.mjs';

const finding = (overrides = {}) => ({ ruleId: 'spectyn.hsts.v1', severity: 'high', title: 'Review transport policy', evidence: 'Missing supplied policy', remediation: 'Review service configuration', target: 'https://example.com', ...overrides });
const report = (overrides = {}) => ({ schemaVersion: 1, tool: { name: 'inspectyn', version: '0.2.0' }, kind: 'review', generatedAt: '2026-10-03T10:00:00.000Z', complete: true, targets: ['https://example.com'], findings: [finding()], errors: [], ...overrides });

test('Inspectyn accepts historical Spectyn reports without changing provenance or rule identifiers', () => {
  const legacy = report({ tool: { name: 'spectyn', version: '0.1.0' }, context: { ruleset: 'spectyn-evidence/1.0' } });
  assert.equal(validateReport(legacy), legacy);
  assert.equal(reportExitCode(legacy), 1);
  for (const format of ['text', 'markdown', 'html']) {
    const output = renderReport(legacy, format);
    assert.match(output, /Inspectyn|INSPECTYN/);
    assert.match(output, /Spectyn 0\.1\.0/);
    assert.match(output, /spectyn\.hsts\.v1/);
    assert.match(output, /spectyn-evidence\/1\.0/);
  }
  const output = JSON.parse(renderReport(legacy, 'json'));
  assert.deepEqual(output.tool, { name: 'spectyn', version: '0.1.0' });
  assert.equal(output.findings[0].ruleId, 'spectyn.hsts.v1');
  assert.equal(output.context.ruleset, 'spectyn-evidence/1.0');
  assert.match(renderReport(report()), /Inspectyn 0\.2\.0/);
});

test('native DNS recon reports round-trip through all JavaScript report formats', () => {
  const recon = report({
    kind: 'recon', targets: ['example.com'], findings: [],
    observations: [{ hostname: 'example.com', observedAt: '2026-10-03T10:00:00.000Z', dns: { mx: { status: 'ok', records: ['10 mail.example.com'] } } }],
    context: { scope: 'Explicit hostnames; DNS records only.' },
  });
  assert.equal(validateReport(recon), recon);
  assert.equal(reportExitCode(recon), 0);
  const json = JSON.parse(renderReport(recon, 'json'));
  assert.equal(json.kind, 'recon');
  assert.deepEqual(json.observations, recon.observations);
  for (const format of ['text', 'markdown', 'html']) {
    const output = renderReport(json, format);
    assert.match(output, /recon/i);
    assert.match(output, /mail\.example\.com/);
    assert.match(output, /Inspectyn 0\.2\.0/);
  }
});

test('expanded native observations survive offline report conversion', () => {
  const expanded = report({
    tool: { name: 'inspectyn', version: '0.3.0-dev' }, kind: 'scan', findings: [],
    observations: [{
      url: 'https://example.com/', hostname: 'example.com', addresses: ['93.184.215.14'], observedAt: '2026-10-04T10:00:00Z',
      dns: { ns: { status: 'ok', records: ['ns.example.com.'] }, cname: { status: 'ok', records: ['edge.example.com.'] } },
      tls: { authorized: true, protocol: 'TLSv1.3', validTo: '2027-01-01T00:00:00Z', issuer: 'CN=<script>fixture</script>', cipherSuite: 'TLS_AES_128_GCM_SHA256', fingerprintSha256: 'ab'.repeat(32), dnsNames: ['example.com'], publicKeyBits: 256 },
      http: { status: 200, headers: {}, cookies: { status: 'ok', total: 1, invalid: 0, items: [{ index: 1, name: '__Host-session', secure: true, httpOnly: true, sameSite: 'lax', domainScoped: false, pathRoot: true, partitioned: false }] } },
      securityTxt: { url: 'https://example.com/.well-known/security.txt', status: 'present', httpStatus: 200, contactCount: 1, expires: '2027-01-01T00:00:00Z', canonicalPresent: true, canonicalMatches: true, signed: false, issues: [] },
    }],
    context: { dnsDetails: true, securityTxt: true },
  });
  const before = structuredClone(expanded);
  const json = JSON.parse(renderReport(expanded, 'json'));
  assert.deepEqual(json.observations, expanded.observations);
  assert.deepEqual(json.context, expanded.context);
  assert.equal(reportExitCode(json), 0);
  for (const format of ['text', 'markdown', 'html']) {
    const output = renderReport(json, format);
    for (const value of ['TLS_AES_128_GCM_SHA256', '__Host-session', 'securityTxt', 'contactCount', 'edge.example.com']) assert.ok(output.includes(value), `${format} lost ${value}`);
  }
  assert.doesNotMatch(renderReport(json, 'html'), /<script>/);
  assert.deepEqual(expanded, before);
});

test('exit codes distinguish threshold, incomplete evidence and successful coverage', () => {
  assert.equal(reportExitCode(report()), 1);
  assert.equal(reportExitCode(report(), 'critical'), 0);
  assert.equal(reportExitCode(report(), 'none'), 0);
  for (const state of ['Observed', 'Not applicable']) assert.equal(reportExitCode(report({ findings: [finding({ state, severity: 'critical' })] }), 'info'), 0);
  assert.equal(reportExitCode(report({ findings: [finding({ state: 'Needs review' })] })), 1);
  assert.equal(reportExitCode(report({ findings: [finding({ severity: 'unknown' })] }), 'info'), 2);
  assert.equal(reportExitCode(report({ findings: [finding({ severity: 'unknown', state:'Needs review' })] }), 'high'), 2);
  assert.equal(reportExitCode(report({ findings: [finding({ severity: 'unknown' })] }), 'none'), 0);
  assert.equal(reportExitCode(report({ findings: [finding({ severity: 'unknown', state:'Not applicable' })] }), 'high'), 0);
  assert.equal(reportExitCode(report({ findings: [] })), 0);
  for (const incomplete of [report({ complete: false }), report({ errors: [{ target: 'https://example.com', code: 'TIMEOUT', message: 'Request timed out' }] }), report({ findings: [finding({ state: 'Not assessable' })] })]) {
    assert.equal(reportExitCode(incomplete), 2);
    assert.equal(reportExitCode(incomplete, 'none'), 2);
    assert.match(renderReport(incomplete), /INCOMPLETE/);
    assert.equal(JSON.parse(renderReport(incomplete, 'json')).coverage.status, 'incomplete');
  }
  assert.throws(() => reportExitCode(report(), 'severe'), /failOn/);
});

test('validation rejects wrong schemas, shapes, excessive values and non-JSON metadata', () => {
  assert.equal(validateReport(report()).schemaVersion, 1);
  for (const invalid of [null, report({ schemaVersion: 2 }), report({ tool: { name: 'other', version: '1' } }), report({ kind: 'unknown' }), report({ generatedAt: '2026-10-03' }), report({ complete: 'yes' }), report({ targets: [null] }), report({ targets: Array(501).fill('x') }), report({ findings: [finding({ severity: 'urgent' })] }), report({ findings: [finding({ state: 'Passed' })] }), report({ findings: [finding({ evidence: 'x'.repeat(16385) })] }), report({ findings: Array(2001).fill(finding()) }), report({ errors: [{ target: 'x', code: 'FAIL' }] }), report({ context: { value: Infinity } }), report({ context: { value: undefined } }), report({ context: { value: new Date() } })]) {
    assert.throws(() => validateReport(invalid), /Invalid Inspectyn report/);
  }
  const circular = {}; circular.self = circular;
  assert.throws(() => validateReport(report({ context: circular })), /circular/);
  let deep = {}; for (let i = 0; i < 20; i++) deep = { nested: deep };
  assert.throws(() => validateReport(report({ context: deep })), /complexity/);
});

test('HTML escapes untrusted evidence and has no executable or remote content', () => {
  const attack = '<script>alert(1)</script><img src="https://evil.example/x" onerror="alert(1)">&\'"';
  const output = renderReport(report({ findings: [finding({ title: attack, evidence: attack, remediation: attack, target: attack })], context: { source: attack }, errors: [{ target: attack, code: attack, message: attack }] }), 'html');
  assert.match(output, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(output, /&amp;&#39;&quot;/);
  assert.doesNotMatch(output, /<script|<img|<[^>]+\ssrc=|<link|<iframe/i);
  assert.match(output, /Content-Security-Policy/);
  assert.match(output, /default-src 'none'/);
  assert.match(output, /INCOMPLETE/);
});

test('text and Markdown remove terminal controls and contain injected Markdown', () => {
  const attack = '\u001b[31mRed\u001b[0m\u001b]8;;https://evil.example\u0007link\u001b]8;;\u0007\r\b\u202e <img src=x> [visit](https://evil.example)\n# forged';
  const input = report({ findings: [finding({ title: attack, evidence: attack, remediation: attack })], context: { note: '```\n# forged\n```', display: attack } });
  for (const format of ['text', 'markdown', 'html']) assert.doesNotMatch(renderReport(input, format), /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202e]/);
  const markdown = renderReport(input, 'markdown');
  assert.match(markdown, /\\<img src=x\\>/);
  assert.match(markdown, /\\\[visit\\\]\\\(https:\/\/evil\.example\\\)/);
  assert.match(markdown, /````json/);
  assert.doesNotMatch(markdown, /^# forged$/m);
  assert.doesNotMatch(renderReport(input), /\[31m|\[0m/);
});

test('all formats preserve meaningful source context and state coverage limitations', () => {
  const input = report({ findings: [], context: { workflow: 'kev-match', catalog: { version: 'snapshot-1', origin: 'User supplied; authenticity not verified' } } });
  const before = JSON.stringify(input);
  for (const format of ['text', 'markdown', 'html', 'json']) {
    const output = renderReport(input, format);
    assert.match(output, /snapshot-1/);
    assert.match(output, /No findings is not assurance/);
  }
  const json = JSON.parse(renderReport(input, 'json'));
  assert.deepEqual(json.context, input.context);
  assert.equal(json.coverage.status, 'complete');
  assert.equal(JSON.stringify(input), before);
  assert.throws(() => renderReport(input, 'pdf'), /format/);
});

test('readable reports preserve CVE, KEV and observation details', () => {
  const input = report({ findings: [finding({ cves: ['CVE-2099-10000'], kev: { state: 'Listed', ids: ['CVE-2099-10000'] }, occurrences: 3, observedAt: '2026-10-01T09:00:00.000Z' })] });
  for (const format of ['text', 'markdown', 'html', 'json']) {
    const output = renderReport(input, format);
    assert.match(output, /CVE-2099-10000/);
    assert.match(output, /Listed/);
    assert.match(output, /occurrences/);
    assert.match(output, /2026-10-01T09:00:00.000Z/);
  }
});
