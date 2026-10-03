import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { reviewEvidence, evidenceRecipes, EVIDENCE_LIMIT } from '../src/review.mjs';

const example = async (name) => readFile(new URL(`../examples/${name}.json`, import.meta.url), 'utf8');
const [headers, nuclei, kev, inventory, advisory] = await Promise.all(
  ['headers', 'nuclei', 'kev', 'inventory', 'advisory'].map(example),
);
const event = (more = {}) => ({
  'template-id': 'sample-rule',
  info: { name: 'Imported candidate', severity: 'high', classification: { 'cve-id': ['CVE-2024-27199'] } },
  host: 'https://app.example.com',
  ...more,
});

test('all four evidence workflows produce the common report shape without network access', () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Network access forbidden'); };
  try {
    const inputs = {
      'http-baseline': [headers],
      'nuclei-review': [nuclei],
      'kev-match': [nuclei, kev],
      'cve-applicability': [inventory, advisory],
    };
    for (const { id } of evidenceRecipes) {
      const report = reviewEvidence(id, ...inputs[id]);
      assert.equal(report.schemaVersion, 1);
      assert.deepEqual(report.tool, { name: 'inspectyn', version: '0.2.0' });
      assert.equal(report.kind, 'review');
      assert.ok(Number.isFinite(Date.parse(report.generatedAt)));
      assert.equal(report.complete, true);
      assert.deepEqual(report.errors, []);
      assert.equal(report.context.workflow, id);
      assert.equal(report.context.ruleset, 'spectyn-evidence/1.0');
      assert.equal(report.context.sample, false);
      assert.ok(report.context.inputRecords > 0);
      assert.deepEqual(report.targets, [...new Set(report.findings.map((finding) => finding.target))]);
      for (const finding of report.findings) {
        for (const key of ['id', 'ruleId', 'title', 'severity', 'state', 'target', 'evidence', 'remediation']) {
          assert.equal(typeof finding[key], 'string', key);
          assert.ok(finding[key], key);
        }
        assert.ok(Array.isArray(finding.cves));
        assert.equal(typeof finding.occurrences, 'number');
        assert.ok('observedAt' in finding);
        assert.ok('firstObservedAt' in finding);
      }
    }
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test('Nuclei JSONL preserves positive-candidate semantics, grouping, skips and observation dates', () => {
  const report = reviewEvidence('nuclei-review', [
    event({ timestamp: '2026-09-18T00:00:00Z' }),
    event({ timestamp: '2026-09-01T00:00:00Z' }),
    event({ 'matcher-status': false }),
    event({ error: 'timeout' }),
  ].map(JSON.stringify).join('\n'));
  assert.equal(report.context.inputRecords, 4);
  assert.equal(report.context.groupedRecords, 1);
  assert.equal(report.context.skippedRecords, 2);
  assert.equal(report.findings.length, 1);
  const finding = report.findings[0];
  assert.equal(finding.state, 'Needs review');
  assert.equal(finding.occurrences, 2);
  assert.equal(finding.observedAt, '2026-09-18T00:00:00.000Z');
  assert.equal(finding.firstObservedAt, '2026-09-01T00:00:00.000Z');
  assert.match(finding.remediation, /does not confirm exploitability/);
  assert.equal(finding.kev.state, 'Unknown');
});

test('KEV matches exact IDs and retains supplied catalogue date and unverifiable provenance', () => {
  const report = reviewEvidence('kev-match', JSON.stringify([
    event(),
    event({ 'template-id': 'other', info: { name: 'Other', classification: { 'cve-id': 'CVE-2024-27198' } } }),
    event({ 'template-id': 'none', info: { name: 'No CVE' } }),
  ]), kev);
  assert.deepEqual(report.findings.map((finding) => finding.kev.state), ['Listed', 'Not listed in supplied catalog', 'Unknown']);
  assert.deepEqual(report.findings[0].kev.ids, ['CVE-2024-27199']);
  assert.equal(report.context.catalog.version, 'sample-fixture');
  assert.equal(report.context.catalog.releasedAt, '2026-09-17');
  assert.match(report.context.catalog.origin, /authenticity not verified/);
  assert.ok(report.findings.every((finding) => finding.state === 'Needs review'));
});

test('HTTP baseline handles absent context, report-only CSP, disabled and duplicate HSTS conservatively', () => {
  assert.deepEqual(reviewEvidence('http-baseline', headers).findings.map((finding) => finding.state), ['Needs review', 'Needs review', 'Observed']);
  const missing = reviewEvidence('http-baseline', JSON.stringify({ asset: 'app.example.com', headers: {} }));
  assert.equal(missing.complete, false);
  assert.deepEqual(missing.findings.map((finding) => finding.state), ['Not assessable', 'Not assessable', 'Needs review']);
  for (const hsts of ['max-age=0', 'max-age=99; max-age=0', ['max-age=99', 'max-age=99']]) {
    const report = reviewEvidence('http-baseline', JSON.stringify({ url: 'https://app.example.com', headers: {
      'Content-Type': 'text/html', 'Strict-Transport-Security': hsts,
    } }));
    assert.equal(report.findings[0].state, 'Needs review');
  }
  const nonHtml = reviewEvidence('http-baseline', JSON.stringify({ url: 'http://app.example.com', headers: {
    'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff',
  } }));
  assert.deepEqual(nonHtml.findings.map((finding) => finding.state), ['Not applicable', 'Not applicable', 'Observed']);
});

test('CVE exact-version comparison preserves candidate/unaffected distinction and advisory context', () => {
  const report = reviewEvidence('cve-applicability', inventory, advisory);
  assert.deepEqual(report.findings.map((finding) => finding.state), ['Needs review', 'Not applicable']);
  assert.equal(report.context.advisory.id, 'CVE-2099-10000');
  assert.equal(report.context.advisory.updatedAt, '2026-09-18T09:00:00.000Z');
  assert.match(report.context.advisory.origin, /authenticity not verified/);
  assert.match(report.findings[0].evidence, /2.4.0.*Fictional inventory/);
  assert.match(report.findings[0].remediation, /candidate does not confirm exploitability/);
  assert.match(report.findings[1].evidence, /only to this advisory/);
});

test('CVE ranges, qualifiers, unknown identity and conflicting versions remain incomplete', () => {
  const compare = (changeInventory, changeAdvisory) => {
    const items = JSON.parse(inventory);
    const record = JSON.parse(advisory);
    changeInventory?.(items[0]);
    changeAdvisory?.(record.containers.cna.affected[0]);
    return reviewEvidence('cve-applicability', JSON.stringify(items), JSON.stringify(record));
  };
  for (const change of [
    (row) => { delete row.vendor; },
    (row) => { delete row.source; },
    (row) => { row.observedAt = 'unknown'; },
    (row) => { row.version = '2.4'; },
    (row) => { row.version = 'unknown'; },
    (row) => { row.product = 'Other service'; },
  ]) {
    const report = compare(change);
    assert.equal(report.complete, false);
    assert.equal(report.findings[0].state, 'Not assessable');
  }
  for (const change of [
    (product) => { product.versions[0].lessThan = '2.5.0'; },
    (product) => { product.versions[0].changes = []; },
    (product) => { product.platforms = ['Linux']; },
    (product) => { product.versions.push({ version: '2.4.0', status: 'unaffected' }); },
    (product) => { product.versions = []; product.defaultStatus = 'unaffected'; },
    (product) => { product.versions[0].version = '*'; },
  ]) {
    const report = compare(undefined, change);
    assert.equal(report.complete, false);
    assert.equal(report.findings[0].state, 'Not assessable');
  }
});

test('reports omit credentials, URL path/query/fragment, raw responses, cookies and advisory material', () => {
  const sensitiveUrl = 'https://user:SECRET_PASS@app.example.com/SECRET_PATH?token=SECRET_QUERY#SECRET_FRAGMENT';
  const nucleiReport = reviewEvidence('nuclei-review', JSON.stringify(event({
    host: sensitiveUrl, request: 'SECRET_REQUEST', response: 'SECRET_RESPONSE',
    'curl-command': 'SECRET_COMMAND', 'template-encoded': 'SECRET_TEMPLATE', 'extracted-results': ['SECRET_EXTRACTED'],
  })));
  const headerReport = reviewEvidence('http-baseline', JSON.stringify({ url: sensitiveUrl, headers: {
    'Set-Cookie': 'SECRET_COOKIE', Authorization: 'SECRET_AUTH', 'Content-Type': 'text/html',
  } }));
  const items = JSON.parse(inventory);
  items[0].asset = sensitiveUrl;
  items[0].request = 'SECRET_REQUEST';
  const record = JSON.parse(advisory);
  record.containers.cna.descriptions = [{ value: 'SECRET_RAW_ADVISORY' }];
  const cveReport = reviewEvidence('cve-applicability', JSON.stringify(items), JSON.stringify(record));
  for (const report of [nucleiReport, headerReport, cveReport]) {
    assert.doesNotMatch(JSON.stringify(report), /SECRET_/);
    assert.equal(report.targets[0], 'https://app.example.com');
  }
});

test('malformed, oversized and unsupported inputs fail without exposing raw input', () => {
  assert.throws(() => reviewEvidence('missing', nuclei), /Unknown evidence workflow/);
  assert.throws(() => reviewEvidence('nuclei-review', `${JSON.stringify(event())}\nSECRET_INVALID`), /Invalid JSON on line 2/);
  assert.throws(() => reviewEvidence('nuclei-review', JSON.stringify([event(), null])), /JSON object/);
  assert.throws(() => reviewEvidence('nuclei-review', ' '.repeat(EVIDENCE_LIMIT) + nuclei), /2 MB/);
  assert.throws(() => reviewEvidence('nuclei-review', JSON.stringify(Array.from({ length: 501 }, () => event()))), /500/);
  assert.throws(() => reviewEvidence('nuclei-review', JSON.stringify(event({ type: 'dns' }))), /HTTP Nuclei/);
  assert.throws(() => reviewEvidence('nuclei-review', JSON.stringify(event({ host: 'file:///SECRET_PATH' }))), /HTTP\(S\)/);
  assert.throws(() => reviewEvidence('http-baseline', '[]'), /at least one/);
  assert.throws(() => reviewEvidence('kev-match', nuclei, '{}'), /vulnerabilities/);
  assert.throws(() => reviewEvidence('cve-applicability', inventory, '{}'), /published CVE Record/);
  assert.throws(() => reviewEvidence('cve-applicability', '[]', advisory), /at least one/);
});
