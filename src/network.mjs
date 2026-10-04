import { Resolver } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import https from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { normalizeTarget } from './config.mjs';

const blocked = new BlockList();
for (const [base, bits] of [ ['0.0.0.0',8], ['10.0.0.0',8], ['100.64.0.0',10], ['127.0.0.0',8],
  ['169.254.0.0',16], ['172.16.0.0',12], ['192.0.0.0',24], ['192.0.2.0',24], ['192.88.99.0',24],
  ['192.168.0.0',16], ['198.18.0.0',15], ['198.51.100.0',24], ['203.0.113.0',24], ['224.0.0.0',4], ['240.0.0.0',4] ]) blocked.addSubnet(base, bits, 'ipv4');
for (const [base,bits] of [['2001::',23], ['2001:db8::',32], ['2002::',16], ['3fff::',20]]) blocked.addSubnet(base,bits,'ipv6');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::',3,'ipv6');
const absentCodes = new Set(['ENODATA', 'ENOTFOUND']);
const headerNames = new Set(['content-type', 'strict-transport-security', 'content-security-policy',
  'content-security-policy-report-only', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy']);

export function isPublicAddress(address) {
  const family = isIP(address);
  return family === 4 ? !blocked.check(address,'ipv4') : family === 6 && globalV6.check(address,'ipv6') && !blocked.check(address,'ipv6');
}

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function safeCode(error) { return typeof error?.code === 'string' && /^[A-Z0-9_]+$/.test(error.code) ? error.code : 'NETWORK_ERROR'; }
function boundedRecords(records) {
  if (records.length > 64 || records.some(x => x.length > 8192) || records.join('').length > 32768) throw failure('DNS_LIMIT', 'DNS response exceeded record limits.');
  return records;
}

export async function resolveTarget(hostname, timeoutMs, includeMail = true, resolver = new Resolver({ timeout: timeoutMs, tries: 1 })) {
  const timer = setTimeout(() => resolver.cancel(), timeoutMs);
  async function query(method, name, transform = value => value) {
    try { return { status: 'ok', records: boundedRecords(transform(await resolver[method](name))) }; }
    catch (error) { return { status: absentCodes.has(error.code) ? 'absent' : 'error', records: [], error: safeCode(error) }; }
  }
  try {
    const jobs = [query('resolve4',hostname), query('resolve6',hostname)];
    if (includeMail) jobs.push(query('resolveTxt',hostname, values => values.map(parts => parts.join(''))),
      query('resolveTxt',`_dmarc.${hostname}`, values => values.map(parts => parts.join(''))),
      query('resolveMx',hostname, values => values.map(value => `${value.priority} ${value.exchange}`)));
    const [v4,v6,txt,dmarc,mx] = await Promise.all(jobs);
    if ([v4,v6].some(value => value.status === 'error')) throw failure('DNS_LOOKUP_FAILED', 'Address resolution was incomplete; no HTTPS request was made.');
    const addresses = [...v4.records, ...v6.records];
    if (!addresses.length) throw failure('DNS_NO_ADDRESS','No A or AAAA address was returned.');
    if (!addresses.every(isPublicAddress)) throw failure('DESTINATION_BLOCKED','The hostname resolves to a private, reserved or unsupported address; no HTTPS request was made.');
    const filter = (result, regex) => ({ ...result, records: result.records.filter(value => regex.test(value)),
      status: result.status === 'error' ? 'error' : result.records.some(value => regex.test(value)) ? 'ok' : 'absent' });
    return { address: addresses[0], family: isIP(addresses[0]), addresses,
      ...(includeMail ? { dns: { spf: filter(txt,/^v=spf1(?:\s|$)/i), dmarc: filter(dmarc,/^v\s*=\s*DMARC1(?:;|\s|$)/i), mx } } : {}) };
  } finally { clearTimeout(timer); }
}

export function pinnedRequestOptions(url, address) {
  if (!isPublicAddress(address)) throw failure('DESTINATION_BLOCKED','The connection address is not public.');
  return { hostname: address, family: isIP(address), port: 443, path: url.pathname, method: 'GET',
    servername: url.hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
    checkServerIdentity: (_host, cert) => checkServerIdentity(url.hostname, cert),
    maxHeaderSize: 32768, headers: { Host: url.hostname, 'User-Agent': 'Inspectyn/0.2.0', Accept: '*/*', Connection: 'close' } };
}

export function requestHeaders(url, address, timeoutMs, request = https.request) {
  return new Promise((resolve,reject) => {
    let settled = false, timer, req;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(error);
      else resolve(result);
    };
    try {
      req = request(pinnedRequestOptions(url,address), response => {
        try {
          const socket = response.socket;
          const expected = new BlockList();
          const family = isIP(address) === 4 ? 'ipv4' : 'ipv6';
          expected.addAddress(address,family);
          if (!socket?.authorized || !socket.remoteAddress || !expected.check(socket.remoteAddress,family)) {
            throw failure('TLS_DESTINATION_MISMATCH','The TLS connection did not reach the validated destination with a valid certificate.');
          }
          const certificate = socket.getPeerCertificate();
          const headers = {};
          // Node's headers view can discard duplicate Content-Type fields.
          for (const [name,value] of Object.entries(response.headersDistinct ?? response.headers)) if (headerNames.has(name)) {
            headers[name] = Array.isArray(value) ? value.length === 1 ? value[0] : value : String(value ?? '');
          }
          const expires = Date.parse(certificate.valid_to);
          finish(null, { http: { status: response.statusCode, headers }, tls: { authorized: true, protocol: socket.getProtocol(),
            validTo: Number.isFinite(expires) ? new Date(expires).toISOString() : null } });
        } catch (error) { finish(error); }
        finally { response.destroy(); req?.destroy(); }
      });
      req.on('error',error => finish(error));
      timer = setTimeout(() => { const error = failure('ETIMEDOUT','HTTPS headers exceeded the request deadline.'); finish(error); req.destroy(); },timeoutMs);
      req.end();
    } catch (error) { finish(error); req?.destroy(); }
  });
}

export async function collectTarget(target, config, dependencies = {}) {
  const url = new URL(normalizeTarget(target));
  const resolved = await (dependencies.resolveTarget ?? resolveTarget)(url.hostname,config.timeoutMs,config.dns);
  const observed = await (dependencies.requestHeaders ?? requestHeaders)(url,resolved.address,config.timeoutMs);
  return { url: url.href, hostname: url.hostname, address: resolved.address, observedAt: new Date().toISOString(), ...observed,
    ...(resolved.dns ? { dns: resolved.dns } : {}) };
}

const certificateDescriptions = {
  CERT_HAS_EXPIRED: 'The TLS certificate has expired.', CERT_NOT_YET_VALID: 'The TLS certificate is not yet valid.',
  ERR_TLS_CERT_ALTNAME_INVALID: 'The TLS certificate does not match the hostname.',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'The TLS certificate is self-signed and untrusted.', SELF_SIGNED_CERT_IN_CHAIN: 'The TLS certificate chain contains an untrusted self-signed certificate.',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'The TLS certificate chain could not be verified.', UNABLE_TO_GET_ISSUER_CERT: 'The TLS certificate chain could not be verified.',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'The TLS certificate chain could not be verified.', CERT_UNTRUSTED: 'The TLS certificate chain could not be verified.',
  CERT_SIGNATURE_FAILURE: 'The TLS certificate signature could not be verified.', CERT_REVOKED: 'The TLS certificate has been revoked.'
};

/** Node TLS verification codes that mean the served certificate failed validation. */
export const CERTIFICATE_ERROR_CODES = new Set(Object.keys(certificateDescriptions));

export function networkError(target,error) {
  const code = safeCode(error);
  const descriptions = {
    DESTINATION_BLOCKED: 'Private, reserved or unsupported destination blocked.', DNS_LOOKUP_FAILED: 'DNS address resolution was incomplete.',
    DNS_NO_ADDRESS: 'No A or AAAA address was returned.', ETIMEDOUT: 'The network operation timed out.',
    TLS_DESTINATION_MISMATCH: 'The connection did not meet the destination and TLS verification requirements.', ...certificateDescriptions
  };
  return { target,code,message: descriptions[code] ?? `Network check could not complete (${code}).` };
}
