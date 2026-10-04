import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.mjs';
import { reportExitCode } from '../src/report.mjs';

const root = fileURLToPath(new URL('../',import.meta.url));
const run = (...args) => spawnSync(process.execPath,[join(root,'bin/inspectyn-js.mjs'),...args],{encoding:'utf8',timeout:10000,cwd:tmpdir()});

test('JavaScript entry point identifies Inspectyn and matches its package version', async () => {
  const version = run('--version');
  assert.equal(version.status, 0, version.stderr);
  assert.equal(version.stdout, '0.2.0\n');
  assert.match(run('--help').stdout, /Inspectyn JS 0\.2\.0/);
  assert.match(run('--help').stdout, /inspectyn-js scan/);
  const metadata = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.equal(metadata.name, '@inspectyn/cli');
  assert.equal(metadata.version, version.stdout.trim());
  assert.deepEqual(metadata.bin, { 'inspectyn-js': 'bin/inspectyn-js.mjs' });
  assert.equal(metadata.private, true);
});

test('standalone command runs outside project, emits valid JSON, and converts to escaped HTML', async () => {
  const directory = await mkdtemp(join(tmpdir(),'inspectyn-cli-'));
  try {
    const report = join(directory,'report.json');
    const result = run('review','http-baseline','--input',join(root,'examples/headers.json'),'--format','json','--out',report);
    assert.equal(result.status,0,result.stderr);
    const data = JSON.parse(await readFile(report,'utf8'));
    assert.equal(data.kind,'review');
    assert.deepEqual(data.tool,{name:'inspectyn',version:'0.2.0'});
    assert.ok(data.findings.length);
    const converted = run('report',report,'--format','html');
    assert.equal(converted.status,0,converted.stderr);
    assert.match(converted.stdout,/<!doctype html>/i);
    assert.equal(run('report',report,'--format','json','--out',report).status,2);
    assert.deepEqual(JSON.parse(await readFile(report,'utf8')),data);
    const threshold = run('report',report,'--fail-on','low');
    assert.equal(threshold.status,1,threshold.stderr);
  } finally { await rm(directory,{recursive:true,force:true}); }
});

test('help/version, invalid arguments and missing evidence have deterministic exit codes', () => {
  assert.equal(run('--help').status,0);
  assert.match(run('--version').stdout,/0\.2\.0/);
  for (const args of [['scan'],['scan','--target','http://company.com'],['scan','--target','https://127.0.0.1'],
    ['review','kev-match','--input','missing.json'],['scan','--target','https://company.com','--format','csv'],
    ['review','http-baseline','--input','missing.json'],['bogus'],['init','--unknown'],['review','http-baseline','--input','x','--advisory','y']]) {
    const result = run(...args);
    assert.equal(result.status,2,JSON.stringify(args));
    assert.equal(result.stdout,'');
  }
});

test('init refuses overwrite and review bounds input before parsing', async () => {
  const directory = await mkdtemp(join(tmpdir(),'inspectyn-cli-'));
  try {
    const config = join(directory,'inspectyn.json');
    assert.equal(run('init','--out',config,'--target','https://company.com').status,0);
    assert.equal(run('init','--out',config).status,2);
    assert.deepEqual(JSON.parse(await readFile(config,'utf8')).targets,['https://company.com/']);
    const huge = join(directory,'huge.json');
    await writeFile(huge,' '.repeat(2*1024*1024+1));
    const result = run('review','http-baseline','--input',huge);
    assert.equal(result.status,2);
    assert.match(result.stderr,/limit/);
  } finally { await rm(directory,{recursive:true,force:true}); }
});

test('scan partial failures keep successful evidence and cannot yield clean CI', async () => {
  const report = await scan({schemaVersion:1,targets:['https://one.company.com','https://two.company.com'],dns:false},async target => {
    if (target.includes('two.')) throw Object.assign(Error('sensitive remote diagnostic'),{code:'ETIMEDOUT'});
    return {url:target,hostname:'one.company.com',http:{status:200,headers:{'content-type':'application/json','strict-transport-security':'max-age=31536000','x-content-type-options':'nosniff'}},
      tls:{authorized:true,protocol:'TLSv1.3',validTo:'2099-01-01T00:00:00Z'}};
  });
  assert.equal(report.observations.length,1);
  assert.deepEqual(report.tool,{name:'inspectyn',version:'0.2.0'});
  assert.equal(report.complete,false);
  assert.equal(report.errors.length,1);
  assert.equal(reportExitCode(report,'none'),2);
  assert.doesNotMatch(JSON.stringify(report),/sensitive remote diagnostic/);
});

test('scan reports every certificate verification failure as a TLS finding', async () => {
  for (const code of ['SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','CERT_NOT_YET_VALID']) {
    const report = await scan({schemaVersion:1,targets:['https://one.company.com'],dns:false},async () => {
      throw Object.assign(Error('sensitive remote diagnostic'),{code});
    });
    assert.deepEqual(report.findings.map(finding => finding.ruleId),['SPECTYN_TLS_INVALID'],code);
    assert.doesNotMatch(report.errors[0].message,/could not complete/,code);
  }
});

test('unknown severity cannot silently pass a gate and malformed JSON never echoes evidence', async () => {
  const args = ['review','cve-applicability','--input',join(root,'examples/inventory.json'),'--advisory',join(root,'examples/advisory.json'),'--format','json'];
  const gated = run(...args);
  assert.equal(gated.status,2);
  assert.equal(JSON.parse(gated.stdout).complete,true);
  assert.match(gated.stderr,/unknown severity/);
  assert.equal(run(...args,'--fail-on','none').status,0);
  const directory = await mkdtemp(join(tmpdir(),'inspectyn-cli-'));
  try {
    const path = join(directory,'invalid.json');
    await writeFile(path,'private-token=this-must-not-be-echoed');
    const result = run('report',path);
    assert.equal(result.status,2);
    assert.doesNotMatch(result.stderr,/this-must-not-be-echoed/);
  } finally { await rm(directory,{recursive:true,force:true}); }
  assert.equal(run('scan','--target','https://one.company.com','--target','https://two.company.com').status,2);
});
