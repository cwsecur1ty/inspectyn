'use strict';

const byId = id => document.getElementById(id);
const state = { session: null, jobs: [], cache: new Map(), selected: null, active: null, ready: false, submitting: false, canceling: null, pollTimer: null, pollBusy: false, selectionRevision: 0, dataRevision: 0, rendered: '', historySignature: '', tab: 'findings', visibleFindings: 30, lastAnnouncement: '' };
const form = byId('run-form');
const kindName = kind => kind === 'recon' ? 'DNS recon' : 'HTTPS scan';
const text = value => value === null || value === undefined ? '' : String(value);
const displayText = value => text(value).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '');
const make = (tag, className, value) => { const node = document.createElement(tag); if (className) node.className = className; if (value !== undefined) node.textContent = displayText(value); return node; };
const countLabel = (count, singular, plural = `${singular}s`) => `${count} ${count === 1 ? singular : plural}`;
const currentKind = () => form.elements.kind.value;
const targetsFromForm = () => byId('targets').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
const selectedJob = () => state.cache.get(state.selected);

function announce(message) {
  if (message === state.lastAnnouncement) return;
  state.lastAnnouncement = message;
  byId('announcements').textContent = message;
}

function dateLabel(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Time unavailable';
}

function fullDateLabel(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }) : displayText(value);
}

function setConnection(connected, message = '') {
  document.querySelector('.session-state').dataset.connected = String(connected);
  byId('connection-state').textContent = connected ? 'Local session' : 'Disconnected';
  byId('connection-error').hidden = connected;
  byId('connection-message').textContent = message;
  state.ready = connected && Boolean(state.session);
  updateFormState();
}

async function api(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  const headers = { Accept: 'application/json', ...options.headers };
  if (options.method && options.method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    headers['X-Inspectyn-Token'] = state.session?.token ?? '';
  }
  try {
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(typeof data.error === 'string' ? data.error : `Request failed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.status) throw error;
    throw new Error('Cannot reach the local server. Check that Inspectyn is still running, then reconnect.');
  } finally { clearTimeout(timer); }
}

function updateMode() {
  const recon = currentKind() === 'recon';
  byId('mode-help').textContent = recon ? 'DNS records for exact names. No endpoint connections or host enumeration.' : 'TLS, response headers, and cookie attributes. Redirects are not followed.';
  byId('target-help').textContent = recon ? 'One hostname or HTTPS origin per line. No endpoint paths.' : 'One authorized HTTPS URL per line. Public hosts on port 443 only.';
  byId('targets').placeholder = recon ? 'your-domain.com\napi.your-domain.com' : 'https://your-domain.com\nhttps://api.your-domain.com/health';
  byId('security-txt').disabled = recon;
  if (recon) byId('security-txt').checked = false;
  clearTargetError();
  updateFormState();
}

function updateFormState() {
  const button = byId('start-run');
  button.disabled = !state.ready || state.submitting || Boolean(state.active);
  button.textContent = state.submitting ? 'Starting run…' : state.active ? 'Run in progress' : currentKind() === 'recon' ? 'Run DNS recon' : 'Run HTTPS checks';
  byId('active-notice').hidden = !state.active;
}

function clearTargetError() {
  byId('target-error').hidden = true;
  byId('targets').removeAttribute('aria-invalid');
}

function validateTargets(targets, kind) {
  const maximum = state.session?.maxTargets ?? 20;
  if (targets.length < 1 || targets.length > maximum) return `Enter between 1 and ${maximum} targets, one per line.`;
  const seen = new Set();
  for (const [index, target] of targets.entries()) {
    let url;
    try { url = new URL(kind === 'recon' && !target.includes('://') ? `https://${target}` : target); } catch { return `Target ${index + 1} needs ${kind === 'recon' ? 'a hostname or HTTPS origin' : 'a complete HTTPS URL'}.`; }
    if (target.length > 2048 || /[\s\\\u0000-\u001f\u007f]/.test(target) || url.protocol !== 'https:' || url.username || url.password || url.search || target.includes('?') || target.includes('#') || (url.port && url.port !== '443')) return `Target ${index + 1} must use HTTPS on port 443, without credentials, query strings, or fragments.`;
    if (!url.hostname.includes('.') || url.hostname.endsWith('.') || url.hostname.includes(':') || !/^[a-z0-9.-]+$/i.test(url.hostname) || /^(?:\d+\.){3}\d+$/.test(url.hostname)) return `Target ${index + 1} needs a fully qualified DNS hostname; IP addresses and wildcards are not supported.`;
    if (kind === 'recon' && url.pathname !== '/') return `Target ${index + 1} includes a path. DNS recon accepts a hostname or HTTPS origin only.`;
    if (seen.has(url.href)) return `Target ${index + 1} duplicates an earlier target.`;
    seen.add(url.href);
  }
  return '';
}

function jobStatus(job) {
  if (job.state === 'running') return { label: state.canceling === job.id ? 'Canceling' : 'Running', tone: 'running' };
  if (job.state === 'canceled') return { label: 'Canceled', tone: 'warning' };
  if (job.state === 'failed') return { label: 'Failed', tone: 'error' };
  if (job.exitCode === 2) return { label: 'Incomplete', tone: 'warning' };
  if (job.exitCode === 1) return { label: 'Gate reached', tone: 'warning' };
  return { label: 'Completed', tone: 'success' };
}

function saveJob(job) {
  if (!job || typeof job.id !== 'string') throw new Error('The local server returned an invalid run.');
  state.cache.set(job.id, job);
  const previous = state.jobs.findIndex(item => item.id === job.id);
  if (previous >= 0) state.jobs[previous] = job;
  else state.jobs.unshift(job);
  state.active = state.jobs.find(item => item.state === 'running')?.id ?? null;
  if (state.canceling === job.id && job.state !== 'running') state.canceling = null;
  updateFormState();
  renderHistory();
}

function renderHistory() {
  const signature = JSON.stringify([state.selected, state.jobs.map(job => [job.id, job.kind, job.targets, job.state, job.createdAt, job.exitCode])]);
  if (signature === state.historySignature) return;
  state.historySignature = signature;
  const focusedId = byId('history-list').contains(document.activeElement) ? document.activeElement.dataset.jobId : null;
  const items = state.jobs.map(job => {
    const item = make('li', 'history-item');
    const button = make('button', 'history-button');
    button.type = 'button';
    button.dataset.jobId = job.id;
    button.setAttribute('aria-current', String(job.id === state.selected));
    const targets = Array.isArray(job.targets) ? job.targets : [];
    const name = targets.length === 1 ? targets[0] : countLabel(targets.length, 'target');
    button.append(make('span', 'history-name', name), make('span', 'history-state', jobStatus(job).label), make('span', 'history-date', `${kindName(job.kind)} · ${dateLabel(job.createdAt)}`));
    button.addEventListener('click', () => void selectJob(job.id));
    item.append(button);
    return item;
  });
  byId('history-list').replaceChildren(...items);
  if (focusedId) [...byId('history-list').querySelectorAll('button')].find(button => button.dataset.jobId === focusedId)?.focus({ preventScroll: true });
  byId('history-empty').hidden = state.jobs.length > 0;
  byId('history-count').textContent = state.jobs.length ? `${state.jobs.length} / ${state.session?.historyLimit ?? 10}` : '';
}

async function selectJob(id) {
  const revision = ++state.selectionRevision;
  state.selected = id;
  state.tab = 'findings';
  state.visibleFindings = 30;
  state.rendered = '';
  renderHistory();
  if (state.cache.has(id)) renderJob(state.cache.get(id));
  else {
    const summary = state.jobs.find(job => job.id === id);
    if (summary) renderJob(summary);
    byId('output-label').textContent = 'Loading details…';
  }
  try {
    const job = await api(`/api/jobs/${encodeURIComponent(id)}`);
    saveJob(job);
    if (revision !== state.selectionRevision) return;
    renderJob(job);
  } catch (error) {
    if (revision !== state.selectionRevision) return;
    byId('job-error').textContent = error.message;
    byId('job-error').hidden = false;
    byId('job-output').hidden = false;
    byId('empty-output').hidden = true;
    announce(error.message);
  }
}

function detailList(entries) {
  const dl = make('dl', 'record-list');
  for (const [label, value] of entries) {
    const row = make('div');
    row.append(make('dt', '', label), make('dd', '', Array.isArray(value) ? value.join('\n') : value));
    dl.append(row);
  }
  return dl;
}

function rawContext(label, value) {
  const detail = make('details', 'raw-context');
  detail.append(make('summary', '', label), make('pre', '', JSON.stringify(value, null, 2)));
  return detail;
}

const observationStatus = value => ({ ok: 'Observed', present: 'Received', absent: 'Not found', error: 'Failed', skipped: 'Not requested', invalid: 'Needs review', unassessed: 'Not assessed', redirect: 'Redirect not followed' })[value] || displayText(value || 'Not available');
const yesNo = value => value ? 'Yes' : 'No';

function renderTLS(tls) {
  const entries = [['Verification', tls.authorized ? 'Certificate and hostname verified' : 'Not verified'], ['Protocol', tls.protocol || 'Not available'], ['Expires', tls.validTo ? fullDateLabel(tls.validTo) : 'Not available']];
  for (const [label, key] of [['Subject', 'subject'], ['Issuer', 'issuer'], ['Cipher suite', 'cipherSuite'], ['Application protocol', 'negotiatedProtocol'], ['Signature algorithm', 'signatureAlgorithm'], ['Serial number', 'serialNumber'], ['SHA-256 fingerprint', 'fingerprintSha256']]) {
    if (tls[key]) entries.push([label, tls[key]]);
  }
  if (tls.validFrom) entries.push(['Valid from', fullDateLabel(tls.validFrom)]);
  if (tls.dnsNames?.length) entries.push(['Certificate names', tls.dnsNames]);
  if (tls.dnsNamesTruncated) entries.push(['Name limit', 'Additional certificate names were omitted.']);
  if (tls.publicKeyAlgorithm) entries.push(['Public key', `${tls.publicKeyAlgorithm}${tls.publicKeyBits ? ` (${tls.publicKeyBits} bits)` : ''}`]);
  if (tls.verifiedChainLength) entries.push(['Verified chain', countLabel(tls.verifiedChainLength, 'certificate')]);
  return detailList(entries);
}

function renderCookies(cookies) {
  const section = make('div', 'cookie-observations');
  section.append(make('h4', '', 'Cookie attributes'), detailList([['Status', observationStatus(cookies.status)], ['Received', cookies.total ?? 0], ['Invalid or unassessed', cookies.invalid ?? 0]]));
  section.append(make('p', 'field-help', 'Cookie values are not recorded. Attributes apply to this response only.'));
  for (const cookie of Array.isArray(cookies.items) ? cookies.items : []) {
    const item = make('details', 'raw-context cookie-item');
    item.append(make('summary', '', `Cookie ${cookie.index ?? ''}${cookie.name ? `: ${cookie.name}` : ''}`), detailList([
      ['Secure', yesNo(cookie.secure)], ['HttpOnly', yesNo(cookie.httpOnly)], ['SameSite', ({ unspecified: 'Not specified', lax: 'Lax', strict: 'Strict', none: 'None' })[cookie.sameSite] || cookie.sameSite || 'Not specified'],
      ['Domain attribute', yesNo(cookie.domainScoped)], ['Path is /', cookie.pathRoot ? 'Yes' : 'No or not set'], ['Partitioned', yesNo(cookie.partitioned)]
    ]));
    section.append(item);
  }
  return section;
}

const securityTXTIssueLabels = {
  INVALID_TARGET: 'The security.txt URL is invalid.',
  REDIRECT_NOT_FOLLOWED: 'The response redirects to another URL; it was not followed.',
  HTTP_STATUS: 'The HTTP status prevented assessment.',
  BODY_LIMIT: 'The response exceeds the 64 KiB size limit.',
  SIGNATURE_UNVERIFIED: 'A signature wrapper was found; the signature was not verified.',
  CONTENT_TYPE: 'The response Content-Type is not text/plain.',
  AMBIGUOUS_CONTENT_TYPE: 'The response has ambiguous Content-Type headers.',
  UTF8: 'The response is not valid UTF-8.',
  INVALID_UTF8: 'The response is not valid UTF-8.',
  LINE_ENDING: 'The response has an unsupported line ending.',
  SYNTAX: 'A field could not be parsed.',
  CONTACT_URI: 'A Contact field contains an invalid URI.',
  EXPIRES_DATE: 'The Expires value is invalid.',
  EXPIRED: 'The expiry date has passed.',
  CONTACT_REQUIRED: 'No valid Contact field was found.',
  EXPIRES_REQUIRED_ONCE: 'Exactly one Expires field is required.',
  CANONICAL_MISMATCH: 'Canonical does not match the requested URL.',
  BODY_READ_FAILED: 'The response body could not be read.',
  TIMEOUT: 'The request timed out.',
  ETIMEDOUT: 'The request timed out.',
  CANCELED: 'The request was canceled.',
  TLS_CERTIFICATE_INVALID: 'The TLS certificate could not be verified.',
  TLS_DESTINATION_MISMATCH: 'The connection did not match the validated destination.',
  DESTINATION_BLOCKED: 'The destination address is outside the permitted scope.',
  NETWORK_ERROR: 'The request failed.'
};

function renderSecurityTXT(observation) {
  const section = make('div', 'security-txt-observation');
  const entries = [['URL', observation.url], ['Status', observationStatus(observation.status)]];
  if (observation.httpStatus) entries.push(['HTTP status', observation.httpStatus]);
  if (['present', 'invalid'].includes(observation.status)) {
    entries.push(['Contact fields', observation.contactCount ?? 0]);
    if (observation.expires) entries.push(['Expires', fullDateLabel(observation.expires)]);
    entries.push(['Canonical', !observation.canonicalPresent ? 'Not present' : observation.canonicalMatches ? 'Matches the requested URL' : 'Does not match the requested URL']);
  }
  if (observation.signed || ['present', 'invalid'].includes(observation.status)) entries.push(['Signature wrapper', observation.signed ? 'Present; signature not verified' : 'Not present']);
  section.append(make('h4', '', 'security.txt'), detailList(entries));
  if (Array.isArray(observation.issues) && observation.issues.length) {
    const issues = make('ul', 'observation-issues');
    issues.append(...observation.issues.map(issue => make('li', '', Object.hasOwn(securityTXTIssueLabels, issue) ? securityTXTIssueLabels[issue] : displayText(issue).toLowerCase().replace(/[_-]+/g, ' '))));
    section.append(issues);
  }
  return section;
}

function renderFindings(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const nodes = findings.slice(0, state.visibleFindings).map(finding => {
    const detail = make('details', 'finding');
    const summary = make('summary');
    const heading = make('span', 'finding-heading');
    const severity = make('span', 'severity', finding.severity ?? 'unknown');
    severity.dataset.level = ['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity) ? finding.severity : 'unknown';
    heading.append(severity, make('span', 'finding-title', finding.title));
    summary.append(heading, make('span', 'finding-target', finding.target));
    const body = make('div', 'finding-detail');
    const metadata = make('p', 'metadata');
    metadata.append(make('span', '', finding.state ?? 'Needs review'), make('code', '', finding.ruleId));
    const dl = make('dl');
    dl.append(make('dt', '', 'Evidence'), make('dd', '', finding.evidence || 'No evidence text supplied.'), make('dt', '', 'Remediation'), make('dd', '', finding.remediation || 'No remediation text supplied.'));
    body.append(metadata, dl);
    detail.append(summary, body);
    return detail;
  });
  if (!nodes.length) nodes.push(make('p', 'result-empty', report.complete ? 'No findings were produced for these checks. Review the observations and coverage before drawing conclusions.' : 'No findings are available from the completed checks. This run is incomplete; review the errors above.'));
  byId('findings-list').replaceChildren(...nodes);
  byId('show-more').hidden = findings.length <= state.visibleFindings;
  byId('show-more').textContent = `Show ${Math.min(30, findings.length - state.visibleFindings)} more findings`;
}

function renderObservations(report) {
  const nodes = (Array.isArray(report.observations) ? report.observations : []).map(observation => {
    const detail = make('details', 'observation');
    const summary = make('summary');
    summary.append(make('span', 'observation-name', observation.url || observation.hostname || 'Target observation'), make('span', 'observation-meta', `Observed ${dateLabel(observation.observedAt)}`));
    const body = make('div', 'observation-body');
    const destination = [];
    if (observation.hostname) destination.push(['Hostname', observation.hostname]);
    if (observation.address) destination.push(['Connected IP', observation.address]);
    if (observation.addresses?.length) destination.push(['Resolved IPs', observation.addresses]);
    if (destination.length) body.append(detailList(destination));
    if (observation.tls) {
      body.append(make('h4', '', 'TLS certificate'), renderTLS(observation.tls));
    }
    if (observation.http) {
      body.append(make('h4', '', `HTTP response ${observation.http.status ?? ''}`));
      const headers = Object.entries(observation.http.headers ?? {});
      body.append(headers.length ? detailList(headers) : make('p', 'field-help', 'No selected response headers were recorded.'));
      if (observation.http.cookies) body.append(renderCookies(observation.http.cookies));
    }
    if (observation.dns) {
      body.append(make('h4', '', 'DNS records'));
      for (const [name, result] of Object.entries(observation.dns)) {
        if (!result || typeof result !== 'object') continue;
        const heading = make('div', 'record-label');
        heading.append(make('strong', '', name === 'cname' ? 'Canonical name' : name.toUpperCase()), make('span', 'quiet', observationStatus(result.status)));
        body.append(heading);
        if (Array.isArray(result.records) && result.records.length) {
          const list = make('ul', 'dns-records');
          list.append(...result.records.map(record => make('li', '', record)));
          body.append(list);
        } else body.append(make('p', 'field-help', result.status === 'skipped' ? 'Not requested.' : result.status === 'error' ? `Lookup failed${result.error ? ` (${displayText(result.error)})` : ''}.` : 'No records returned.'));
      }
    }
    if (observation.securityTxt) body.append(renderSecurityTXT(observation.securityTxt));
    body.append(rawContext('Raw observation', observation));
    detail.append(summary, body);
    return detail;
  });
  if (!nodes.length) nodes.push(make('p', 'result-empty', 'No endpoint observations were recorded for this run.'));
  if (report.context) nodes.push(rawContext('Run context and coverage', report.context));
  byId('observations-list').replaceChildren(...nodes);
}

function setTab(tab, focus = false) {
  state.tab = tab;
  for (const name of ['findings', 'observations']) {
    const selected = name === tab;
    const button = byId(`${name}-tab`);
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
    byId(`${name}-view`).hidden = !selected;
    if (selected && focus) button.focus();
  }
}

function renderJob(job) {
  const signature = JSON.stringify([job, state.canceling === job.id]);
  if (signature === state.rendered) return;
  state.rendered = signature;
  byId('empty-output').hidden = true;
  byId('job-output').hidden = false;
  byId('output-label').textContent = job.state === 'running' ? 'Live run' : 'Saved in this session';
  byId('job-title').textContent = kindName(job.kind);
  const status = jobStatus(job);
  byId('job-state').textContent = status.label;
  byId('job-state').dataset.tone = status.tone;
  byId('job-meta').textContent = `${countLabel(job.targets?.length ?? 0, 'target')} · Started ${dateLabel(job.createdAt)}${job.finishedAt ? ` · Finished ${dateLabel(job.finishedAt)}` : ''}`;
  byId('running-state').hidden = job.state !== 'running';
  byId('running-copy').textContent = state.canceling === job.id ? 'Cancellation requested. Waiting for active checks to stop.' : job.kind === 'recon' ? 'Querying DNS records for the configured names. No endpoint connections are made.' : 'Checking the configured endpoints. Results will appear when the run finishes.';
  byId('cancel-run').hidden = job.state !== 'running';
  byId('cancel-run').disabled = state.canceling === job.id;
  byId('cancel-run').textContent = state.canceling === job.id ? 'Canceling…' : 'Cancel run';
  const errorMessage = job.error || (job.state === 'canceled' ? 'This run was canceled. Any available results are incomplete.' : job.state === 'failed' ? 'The run could not complete. Review the targets and try again.' : '');
  byId('job-error').textContent = errorMessage;
  byId('job-error').hidden = !errorMessage;
  const report = job.report;
  byId('report-output').hidden = !report;
  byId('download-error').hidden = true;
  if (report) {
    const findings = Array.isArray(report.findings) ? report.findings : [];
    const observations = Array.isArray(report.observations) ? report.observations : [];
    byId('report-summary').textContent = `${countLabel(findings.length, 'finding')} · ${countLabel(observations.length, 'observation')}${job.exitCode !== undefined ? ` · Exit code ${job.exitCode}` : ''}`;
    byId('report-coverage').textContent = `${report.complete ? '' : 'Incomplete evidence. '}${report.context?.scope || 'Only the configured targets and requested checks were assessed.'} No findings does not establish that a target is secure.`;
    const errors = Array.isArray(report.errors) ? report.errors : [];
    byId('report-errors').hidden = errors.length === 0;
    byId('errors-list').replaceChildren(...errors.map(error => make('li', '', `${error.target || 'Target'} — ${error.message || error.code || 'Check failed'}`)));
    byId('findings-tab').textContent = `Findings (${findings.length})`;
    byId('observations-tab').textContent = `Observations (${observations.length})`;
    renderFindings(report);
    renderObservations(report);
    setTab(state.tab);
  }
  announce(`${kindName(job.kind)} ${status.label.toLowerCase()}${job.exitCode !== undefined ? `, exit code ${job.exitCode}` : ''}.`);
}

async function refreshJobs() {
  const revision = state.dataRevision;
  const response = await api('/api/jobs');
  if (revision !== state.dataRevision) return;
  state.jobs = (Array.isArray(response.jobs) ? response.jobs : []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  state.active = state.jobs.find(job => job.state === 'running')?.id ?? null;
  if (state.canceling && !state.jobs.some(job => job.id === state.canceling && job.state === 'running')) state.canceling = null;
  const available = new Set(state.jobs.map(job => job.id));
  for (const id of state.cache.keys()) if (!available.has(id)) state.cache.delete(id);
  if (!state.selected || !available.has(state.selected)) {
    state.selected = state.active ?? state.jobs[0]?.id ?? null;
    state.rendered = '';
    state.visibleFindings = 30;
  }
  renderHistory();
  updateFormState();
  if (state.selected) {
    const summary = state.jobs.find(job => job.id === state.selected);
    const cached = state.cache.get(state.selected);
    if (!cached || cached.state === 'running' || cached.state !== summary.state) {
      const id = state.selected;
      const job = await api(`/api/jobs/${encodeURIComponent(id)}`);
      saveJob(job);
      if (state.selected === id) renderJob(job);
    } else renderJob(cached);
  } else {
    byId('empty-output').hidden = false;
    byId('job-output').hidden = true;
    byId('output-label').textContent = 'No run selected';
  }
}

function schedulePoll() {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(async () => {
    if (state.pollBusy || state.submitting) { schedulePoll(); return; }
    if (!state.session) { await startSession(); return; }
    state.pollBusy = true;
    try { await refreshJobs(); setConnection(true); }
    catch (error) { setConnection(false, error.message); }
    finally { state.pollBusy = false; schedulePoll(); }
  }, state.active ? 1000 : 5000);
}

async function startSession() {
  clearTimeout(state.pollTimer);
  byId('reconnect').disabled = true;
  try {
    const session = await api('/api/session');
    if (typeof session.token !== 'string' || !session.token) throw new Error('The local session could not be initialized. Reconnect to try again.');
    state.session = session;
    byId('version').textContent = `v${text(session.version)}`;
    byId('target-limit').textContent = `Up to ${session.maxTargets ?? 20} targets`;
    byId('history-note').textContent = `The latest ${session.historyLimit ?? 10} runs stay in server memory. Download reports before stopping Inspectyn.`;
    updateTargetCount();
    await refreshJobs();
    setConnection(true);
  } catch (error) { setConnection(false, error.message); }
  finally { byId('reconnect').disabled = false; schedulePoll(); }
}

function updateTargetCount() {
  byId('target-count').textContent = `${targetsFromForm().length} / ${state.session?.maxTargets ?? 20}`;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!state.ready || state.submitting || state.active) return;
  byId('form-error').hidden = true;
  clearTargetError();
  const targets = targetsFromForm();
  const error = validateTargets(targets, currentKind());
  if (error) {
    byId('target-error').textContent = error;
    byId('target-error').hidden = false;
    byId('targets').setAttribute('aria-invalid', 'true');
    byId('targets').focus();
    announce(error);
    return;
  }
  for (const id of ['timeout', 'concurrency']) {
    if (!byId(id).validity.valid) { byId('advanced').open = true; byId(id).reportValidity(); return; }
  }
  const request = { kind: currentKind(), targets, dns: byId('dns').checked, dnsDetails: byId('dns-details').checked, securityTxt: currentKind() === 'scan' && byId('security-txt').checked, timeoutMs: Number(byId('timeout').value), concurrency: Number(byId('concurrency').value), failOn: byId('fail-on').value };
  state.submitting = true;
  state.dataRevision++;
  updateFormState();
  try {
    const job = await api('/api/jobs', { method: 'POST', body: JSON.stringify(request) });
    saveJob(job);
    state.selected = job.id;
    state.selectionRevision++;
    state.rendered = '';
    state.tab = 'findings';
    state.visibleFindings = 30;
    renderHistory();
    renderJob(job);
    schedulePoll();
  } catch (error) {
    byId('form-error').textContent = error.message;
    byId('form-error').hidden = false;
    byId('form-error').focus();
    if (error.status === 409) { try { await refreshJobs(); } catch { /* The original busy message remains visible. */ } }
    if (error.status === 403) { state.session = null; setConnection(false, 'The local session changed. Reconnect before starting another run.'); }
  } finally { state.submitting = false; updateFormState(); }
});

byId('cancel-run').addEventListener('click', async () => {
  const job = selectedJob();
  if (!job || job.state !== 'running' || state.canceling === job.id) return;
  state.canceling = job.id;
  state.dataRevision++;
  renderJob(job);
  try {
    const updated = await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, { method: 'POST', body: '{}' });
    saveJob(updated);
    if (state.selected === updated.id) renderJob(updated);
  } catch (error) {
    state.canceling = null;
    if (state.selected === job.id) { state.rendered = ''; renderJob(job); byId('job-error').textContent = error.message; byId('job-error').hidden = false; }
    announce(error.message);
  }
  schedulePoll();
});

byId('download-report').addEventListener('click', async () => {
  const job = selectedJob();
  if (!job?.report) return;
  const button = byId('download-report');
  button.disabled = true;
  button.textContent = 'Preparing…';
  byId('download-error').hidden = true;
  const format = byId('download-format').value;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`/api/jobs/${encodeURIComponent(job.id)}/report?format=${encodeURIComponent(format)}`, { credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
    if (!response.ok) { const result = await response.json().catch(() => ({})); throw new Error(result.error || 'The report could not be downloaded. Try again.'); }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = make('a');
    link.href = url;
    link.download = `inspectyn-${job.kind}-${job.id.replace(/[^a-zA-Z0-9_-]/g, '')}.${({ json: 'json', html: 'html', markdown: 'md', text: 'txt' })[format]}`;
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    announce(`${format.toUpperCase()} report download prepared.`);
  } catch (error) { if (state.selected === job.id) { byId('download-error').textContent = error.name === 'AbortError' ? 'The report download timed out. Check the local server and try again.' : error.message; byId('download-error').hidden = false; } }
  finally { clearTimeout(timeout); button.disabled = false; button.textContent = 'Download'; }
});

byId('targets').addEventListener('input', () => { updateTargetCount(); clearTargetError(); });
form.querySelectorAll('input[name="kind"]').forEach(input => input.addEventListener('change', updateMode));
byId('view-active').addEventListener('click', () => { if (state.active) void selectJob(state.active); });
byId('reconnect').addEventListener('click', () => void startSession());
byId('show-more').addEventListener('click', () => { state.visibleFindings += 30; if (selectedJob()?.report) renderFindings(selectedJob().report); });
for (const name of ['findings', 'observations']) {
  byId(`${name}-tab`).addEventListener('click', () => setTab(name));
  byId(`${name}-tab`).addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    setTab(event.key === 'Home' ? 'findings' : event.key === 'End' ? 'observations' : name === 'findings' ? 'observations' : 'findings', true);
  });
}
window.addEventListener('pagehide', () => clearTimeout(state.pollTimer));
updateMode();
void startSession();
