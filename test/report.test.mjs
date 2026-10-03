import test from 'node:test';
import assert from 'node:assert/strict';
import { renderReport, reportExitCode, validateReport } from '../src/report.mjs';

const finding = (overrides = {}) => ({ ruleId: 'spectyn.hsts.v1', severity: 'high', title: 'Review transport policy', evidence: 'Missing supplied policy', remediation: 'Review service configuration', target: 'https://example.com', ...overrides });
const report = (overrides = {}) => ({ schemaVersion: 1, tool: { name: 'spectyn', version: '0.1.0' }, kind: 'review', generatedAt: '2026-10-03T10:00:00.000Z', complete: true, targets: ['https://example.com'], findings: [finding()], errors: [], ...overrides });

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
    assert.throws(() => validateReport(invalid), /Invalid Spectyn report/);
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
