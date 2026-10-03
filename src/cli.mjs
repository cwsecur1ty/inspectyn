import { parseArgs } from 'node:util';
import { DEFAULT_CONFIG, normalizeTarget, validateConfig } from './config.mjs';
import { readBounded, writeNewFile } from './io.mjs';
import { scan } from './scan.mjs';
import { evidenceRecipes, reviewEvidence, EVIDENCE_LIMIT, CATALOG_LIMIT } from './review.mjs';
import { renderReport, validateReport, reportExitCode } from './report.mjs';

export const HELP = `Inspectyn JS 0.2.0 — HTTPS checks and evidence review

Usage:
  inspectyn-js init [--target https://your-domain.com] [--out inspectyn.json]
  inspectyn-js scan --config inspectyn.json [--format text|json|markdown|html] [--out report.json]
  inspectyn-js scan --target https://your-domain.com [--format json]
  inspectyn-js review <workflow> --input evidence.json [--catalog kev.json | --advisory cve.json]
  inspectyn-js report report.json [--format text|json|markdown|html] [--out report.html]

Workflows: nuclei-review, kev-match, http-baseline, cve-applicability
Common report options: --format (default text), --out (default stdout), --fail-on (default high)
Fail levels: info, low, medium, high, critical, none
Exit codes: 0 complete and below threshold; 1 findings at threshold; 2 error/incomplete/unknown gate.

scan contacts only the explicitly supplied public HTTPS endpoints and DNS resolver.
review/report work offline. No account, API key, telemetry or hosted service is required.
Files are never overwritten. Use a new output path for each run.
`;

const allowed = {
  init: ['target','out'], scan:['target','config','format','out','fail-on'],
  review:['input','catalog','advisory','format','out','fail-on'], report:['format','out','fail-on']
};
const scrub = value => String(value).replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g,'').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/[\u0000-\u001f\u007f-\u009f]/g,' ');
function parseJson(text,label) {
  try { return JSON.parse(text); } catch { throw new Error(`${label} must contain valid JSON.`); }
}

export async function main(argv, streams = { stdout:process.stdout, stderr:process.stderr }) {
  try {
    const {values,positionals,tokens} = parseArgs({ args:argv,allowPositionals:true,strict:true,tokens:true,options:{
      help:{type:'boolean',short:'h'},version:{type:'boolean',short:'v'},
      ...Object.fromEntries(['target','out','config','format','fail-on','input','catalog','advisory'].map(key=>[key,{type:'string'}]))
    } });
    const seenOptions = new Set();
    for (const token of tokens) if (token.kind === 'option') {
      if (seenOptions.has(token.name)) throw new Error(`--${token.name} may only be supplied once.`);
      seenOptions.add(token.name);
    }
    if (values.help || argv.length === 0) { streams.stdout.write(HELP); return 0; }
    if (values.version) { streams.stdout.write('0.2.0\n'); return 0; }
    const [command,argument,...extra] = positionals;
    if (!Object.hasOwn(allowed,command)) throw new Error('Unknown command. Run inspectyn-js --help.');
    if (extra.length || (['init','scan'].includes(command) && argument)) throw new Error('Unexpected positional argument.');
    for (const key of Object.keys(values)) if (!allowed[command].includes(key)) throw new Error(`--${key} is not supported by ${command}.`);
    const format = values.format ?? 'text', failOn = values['fail-on'] ?? 'high';
    if (!['text','json','markdown','html'].includes(format)) throw new Error('format must be text, json, markdown or html.');
    if (!['none','info','low','medium','high','critical'].includes(failOn)) throw new Error('Unknown fail-on severity.');
    if (command === 'init') {
      const config = {...DEFAULT_CONFIG,targets:values.target ? [normalizeTarget(values.target)] : []};
      const path = values.out ?? 'inspectyn.json';
      await writeNewFile(path,JSON.stringify(config,null,2)+'\n');
      streams.stdout.write(`Created ${scrub(path)}. ${config.targets.length ? 'Run scan when ready.' : 'Add your explicit HTTPS targets before scanning.'}\n`);
      return 0;
    }
    let report;
    if (command === 'scan') {
      if (!!values.config === !!values.target) throw new Error('Supply exactly one of --config or --target.');
      const config = values.config ? parseJson(await readBounded(values.config,65536),'Configuration') : {...DEFAULT_CONFIG,targets:[values.target]};
      report = await scan(validateConfig(config));
    } else if (command === 'review') {
      if (!argument || !evidenceRecipes.some(recipe=>recipe.id === argument)) throw new Error('Choose a workflow: nuclei-review, kev-match, http-baseline, cve-applicability.');
      if (!values.input) throw new Error('review requires --input.');
      if (argument === 'kev-match' && !values.catalog) throw new Error('kev-match requires --catalog.');
      if (argument === 'cve-applicability' && !values.advisory) throw new Error('cve-applicability requires --advisory.');
      if (values.catalog && argument !== 'kev-match') throw new Error('--catalog is supported only by kev-match.');
      if (values.advisory && argument !== 'cve-applicability') throw new Error('--advisory is supported only by cve-applicability.');
      const input = await readBounded(values.input,EVIDENCE_LIMIT);
      const supplement = values.catalog ? await readBounded(values.catalog,CATALOG_LIMIT) : values.advisory ? await readBounded(values.advisory,EVIDENCE_LIMIT) : '';
      report = reviewEvidence(argument,input,supplement);
    } else {
      if (!argument) throw new Error('report requires an Inspectyn JSON report file.');
      report = parseJson(await readBounded(argument,10*1024*1024),'Report');
    }
    validateReport(report);
    const output = renderReport(report,format);
    if (values.out) await writeNewFile(values.out,output.endsWith('\n') ? output : output+'\n');
    else streams.stdout.write(output.endsWith('\n') ? output : output+'\n');
    const code = reportExitCode(report,failOn);
    if (failOn !== 'none' && report.findings.some(finding => finding.severity === 'unknown' && (finding.state === undefined || finding.state === 'Needs review'))) {
      streams.stderr.write('inspectyn-js: The severity gate cannot be evaluated for an actionable finding with unknown severity. Review the evidence; --fail-on none explicitly disables severity gating.\n');
    }
    return code;
  } catch (error) {
    streams.stderr.write(`inspectyn-js: ${scrub(error.message)}\n`);
    return 2;
  }
}
