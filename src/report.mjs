const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical', 'unknown'];
const STATES = ['Needs review', 'Observed', 'Not assessable', 'Not applicable'];
const COVERAGE = 'This report covers only the supplied evidence or explicitly requested checks. No findings is not assurance that a target is secure. Observations and review candidates do not establish exploitability.';
const MAX_REPORT_BYTES = 10 * 1024 * 1024;

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function fail(message) { throw new Error(`Invalid Spectyn report: ${message}`); }
function string(value, label, limit = 16384, allowEmpty = false) {
  if (typeof value !== 'string' || (!allowEmpty && !value.trim()) || value.length > limit) fail(`${label} must be ${allowEmpty ? 'a' : 'a nonempty'} string of at most ${limit} characters.`);
}
function list(value, label, limit) {
  if (!Array.isArray(value) || value.length > limit) fail(`${label} must be an array of at most ${limit} entries.`);
}
function validateJson(value, depth = 0, budget = { nodes: 0 }, ancestors = new Set()) {
  if (++budget.nodes > 100000 || depth > 16) fail('metadata exceeds the complexity limit.');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('metadata numbers must be finite.'); return; }
  if (typeof value === 'string') { if (value.length > 65536) fail('metadata strings exceed the length limit.'); return; }
  if (!object(value) && !Array.isArray(value)) fail('all fields must contain JSON values.');
  if (ancestors.has(value)) fail('metadata contains a circular reference.');
  if (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('metadata must contain plain JSON objects.');
  ancestors.add(value);
  for (const [key, child] of Object.entries(value)) {
    if (key.length > 256) fail('metadata field names exceed the length limit.');
    validateJson(child, depth + 1, budget, ancestors);
  }
  ancestors.delete(value);
}

/** Validate a portable report without interpreting supplied findings as verified facts. */
export function validateReport(report) {
  if (!object(report) || report.schemaVersion !== 1) fail('expected schemaVersion 1.');
  if (!object(report.tool) || report.tool.name !== 'spectyn') fail('expected tool.name "spectyn".');
  string(report.tool.version, 'tool.version', 80);
  if (!['scan', 'review'].includes(report.kind)) fail('kind must be scan or review.');
  string(report.generatedAt, 'generatedAt', 50);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(report.generatedAt) || !Number.isFinite(Date.parse(report.generatedAt))) fail('generatedAt must be an ISO timestamp with a timezone.');
  if (typeof report.complete !== 'boolean') fail('complete must be boolean.');
  list(report.targets, 'targets', 500);
  report.targets.forEach((target, index) => string(target, `targets[${index}]`, 2048));
  list(report.findings, 'findings', 2000);
  for (const [index, finding] of report.findings.entries()) {
    if (!object(finding)) fail(`findings[${index}] must be an object.`);
    string(finding.ruleId, `findings[${index}].ruleId`, 256);
    string(finding.target, `findings[${index}].target`, 2048);
    string(finding.title, `findings[${index}].title`, 2048);
    string(finding.evidence, `findings[${index}].evidence`, 16384, true);
    string(finding.remediation, `findings[${index}].remediation`, 16384, true);
    if (!SEVERITIES.includes(finding.severity)) fail(`findings[${index}].severity is unsupported.`);
    if (finding.state !== undefined && !STATES.includes(finding.state)) fail(`findings[${index}].state is unsupported.`);
  }
  list(report.errors, 'errors', 500);
  for (const [index, error] of report.errors.entries()) {
    if (!object(error)) fail(`errors[${index}] must be an object.`);
    string(error.target, `errors[${index}].target`, 2048);
    string(error.code, `errors[${index}].code`, 256);
    string(error.message, `errors[${index}].message`, 16384);
  }
  validateJson(report);
  if (Buffer.byteLength(JSON.stringify(report), 'utf8') > MAX_REPORT_BYTES) fail('serialized report exceeds 10 MiB.');
  return report;
}

function incomplete(report) {
  return !report.complete || report.errors.length > 0 || report.findings.some(finding => finding.state === 'Not assessable');
}

/** 2: incomplete/error/indeterminate gate, 1: gate reached, 0: below gate. */
export function reportExitCode(report, failOn = 'high') {
  validateReport(report);
  if (!['none', 'info', 'low', 'medium', 'high', 'critical'].includes(failOn)) throw new Error('failOn must be none, info, low, medium, high or critical.');
  if (incomplete(report)) return 2;
  if (failOn === 'none') return 0;
  if (report.findings.some(finding => finding.severity === 'unknown' && (finding.state === undefined || finding.state === 'Needs review'))) return 2;
  const threshold = SEVERITIES.indexOf(failOn);
  return report.findings.some(finding =>
    (finding.state === undefined || finding.state === 'Needs review') && finding.severity !== 'unknown' && SEVERITIES.indexOf(finding.severity) >= threshold
  ) ? 1 : 0;
}

// Remove terminal escape sequences, control characters and bidi overrides from display output.
const clean = value => String(value)
  .replace(/\u001b\][\s\S]*?(?:\u0007|\u001b\\|$)/g, '')
  .replace(/\u001b[P^_][\s\S]*?(?:\u001b\\|$)/g, '')
  .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
  .replace(/\u001b[@-_]/g, '')
  .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '');
const line = value => clean(value).replace(/[\n\t\u2028\u2029]+/g, ' ');
const escapeHtml = value => clean(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const escapeMarkdown = value => line(value).replace(/[\\`*_{}\[\]()<>#!|~]/g, '\\$&');
const displayJson = value => clean(JSON.stringify(value, (_key, item) => typeof item === 'string' ? clean(item) : item, 2));
function markdownJson(value) {
  const serialized = displayJson(value);
  const fence = '`'.repeat(Math.max(3, ...[...serialized.matchAll(/`+/g)].map(match => match[0].length + 1)));
  return `${fence}json\n${serialized}\n${fence}`;
}

function metadata(report) {
  const excluded = new Set(['schemaVersion', 'tool', 'kind', 'generatedAt', 'complete', 'targets', 'findings', 'errors', 'coverage']);
  return Object.fromEntries(Object.entries(report).filter(([key]) => !excluded.has(key)));
}

function findingMetadata(finding) {
  const excluded = new Set(['id', 'ruleId', 'severity', 'title', 'evidence', 'remediation', 'target', 'state']);
  return Object.fromEntries(Object.entries(finding).filter(([key]) => !excluded.has(key)));
}

function renderText(report) {
  const lines = [
    `SPECTYN ${line(report.kind).toUpperCase()} REPORT`,
    `Status: ${incomplete(report) ? 'INCOMPLETE — errors or evidence gaps require attention' : 'Complete for requested checks'}`,
    `Generated: ${line(report.generatedAt)} | Spectyn ${line(report.tool.version)}`,
    `Targets: ${report.targets.length} | Findings: ${report.findings.length} | Errors: ${report.errors.length}`,
    '', COVERAGE,
  ];
  if (report.targets.length) lines.push('', 'Targets', ...report.targets.map(target => `  ${line(target)}`));
  const context = metadata(report);
  if (Object.keys(context).length) lines.push('', 'Source and workflow context', displayJson(context));
  lines.push('', 'Findings');
  if (!report.findings.length) lines.push('  No findings were produced for this coverage.');
  for (const finding of report.findings) {
    lines.push(`  [${finding.severity.toUpperCase()}] ${line(finding.title)}`, `  Target: ${line(finding.target)} | Rule: ${line(finding.ruleId)} | State: ${finding.state ?? 'Needs review'}`, `  Evidence: ${line(finding.evidence)}`, `  Remediation: ${line(finding.remediation)}`, '');
    const observation = findingMetadata(finding);
    if (Object.keys(observation).length) lines.push('  Observation context', ...displayJson(observation).split('\n').map(value => `  ${value}`), '');
  }
  if (report.errors.length) lines.push('Errors', ...report.errors.map(error => `  ${line(error.target)} [${line(error.code)}]: ${line(error.message)}`));
  return `${lines.join('\n').trimEnd()}\n`;
}

function renderMarkdown(report) {
  const md = escapeMarkdown;
  const lines = ['# Spectyn security report', '', `**Status:** ${incomplete(report) ? 'INCOMPLETE — errors or evidence gaps require attention' : 'Complete for requested checks'}`, '', `Generated: ${md(report.generatedAt)} · Spectyn ${md(report.tool.version)} · ${md(report.kind)}`, '', `Targets: ${report.targets.length} · Findings: ${report.findings.length} · Errors: ${report.errors.length}`, '', COVERAGE, '', '## Targets', '', ...report.targets.map(target => `- ${md(target)}`)];
  if (!report.targets.length) lines.push('No targets recorded.');
  const context = metadata(report);
  if (Object.keys(context).length) {
    lines.push('', '## Source and workflow context', '', markdownJson(context));
  }
  lines.push('', '## Findings', '');
  if (!report.findings.length) lines.push('No findings were produced for this coverage.');
  for (const finding of report.findings) {
    lines.push(`### ${md(finding.title)}`, '', `**Severity:** ${finding.severity} · **State:** ${finding.state ?? 'Needs review'}`, '', `**Target:** ${md(finding.target)} · **Rule:** ${md(finding.ruleId)}`, '', `**Evidence:** ${md(finding.evidence)}`, '', `**Remediation:** ${md(finding.remediation)}`, '');
    const observation = findingMetadata(finding);
    if (Object.keys(observation).length) lines.push('**Observation context**', '', markdownJson(observation), '');
  }
  if (report.errors.length) lines.push('', '## Errors', '', ...report.errors.map(error => `- **${md(error.target)}** (${md(error.code)}): ${md(error.message)}`));
  return `${lines.join('\n').trimEnd()}\n`;
}

function renderHtml(report) {
  const html = escapeHtml, context = metadata(report);
  const findings = report.findings.map(finding => {
    const observation = findingMetadata(finding);
    return `<article><h3>${html(finding.title)}</h3><p class="meta">${html(finding.severity.toUpperCase())} · ${html(finding.state ?? 'Needs review')}</p><dl><dt>Target / rule</dt><dd>${html(finding.target)} / ${html(finding.ruleId)}</dd><dt>Evidence</dt><dd>${html(finding.evidence)}</dd><dt>Remediation</dt><dd>${html(finding.remediation)}</dd></dl>${Object.keys(observation).length ? `<p><strong>Observation context</strong></p><pre>${html(displayJson(observation))}</pre>` : ''}</article>`;
  }).join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Spectyn security report</title><style>body{font:16px/1.6 system-ui,sans-serif;color:#172638;background:#f4f6f8;margin:0}main{max-width:960px;margin:40px auto;padding:32px;background:white;border:1px solid #d7dee7}h1,h2,h3{line-height:1.25}h1{margin-top:0}h2{margin-top:36px}.status{font-weight:700;padding:14px;border-left:4px solid #376785;background:#eef4f7}.incomplete{border-color:#996012;background:#fff6e7}.meta,dt{color:#536276}.coverage{padding:16px;background:#f4f6f8}article{border-top:1px solid #d7dee7;padding:16px 0}dt{font-weight:600}dd{margin:0 0 14px;white-space:pre-wrap;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;background:#f4f6f8}li{overflow-wrap:anywhere}@media(max-width:640px){main{margin:0;padding:20px;border:0}}@media print{body{background:white}main{margin:0;border:0;padding:0}article{break-inside:avoid}}</style></head>
<body><main><h1>Spectyn security report</h1><p class="status${incomplete(report) ? ' incomplete' : ''}">${incomplete(report) ? 'INCOMPLETE — errors or evidence gaps require attention' : 'Complete for requested checks'}</p><p class="meta">${html(report.generatedAt)} · Spectyn ${html(report.tool.version)} · ${html(report.kind)}</p><p>Targets: ${report.targets.length} · Findings: ${report.findings.length} · Errors: ${report.errors.length}</p><p class="coverage">${COVERAGE}</p><h2>Targets</h2>${report.targets.length ? `<ul>${report.targets.map(target => `<li>${html(target)}</li>`).join('')}</ul>` : '<p>No targets recorded.</p>'}
${Object.keys(context).length ? `<h2>Source and workflow context</h2><pre>${html(displayJson(context))}</pre>` : ''}
<h2>Findings</h2>${findings || '<p>No findings were produced for this coverage.</p>'}
${report.errors.length ? `<h2>Errors</h2><ul>${report.errors.map(error => `<li><strong>${html(error.target)}</strong> (${html(error.code)}): ${html(error.message)}</li>`).join('')}</ul>` : ''}
</main></body></html>\n`;
}

/** Produce a self-contained report; JSON retains the original evidence strings. */
export function renderReport(report, format = 'text') {
  validateReport(report);
  if (format === 'json') return `${JSON.stringify({ ...report, coverage: { status: incomplete(report) ? 'incomplete' : 'complete', statement: COVERAGE } }, null, 2)}\n`;
  if (format === 'text') return renderText(report);
  if (format === 'markdown') return renderMarkdown(report);
  if (format === 'html') return renderHtml(report);
  throw new Error('Report format must be text, json, markdown or html.');
}
