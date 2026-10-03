import { isIP } from 'node:net';

export const DEFAULT_CONFIG = { schemaVersion: 1, targets: [], dns: true, timeoutMs: 10000 };

export function normalizeTarget(value) {
  if (typeof value !== 'string' || value.length > 2048 || /[\s\u0000-\u001f\u007f\\]/.test(value)) {
    throw new Error('Targets must be HTTPS URLs without whitespace or control characters.');
  }
  let url;
  try { url = new URL(value); } catch { throw new Error('Targets must be complete HTTPS URLs.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.port && url.port !== '443')) {
    throw new Error('Use HTTPS on port 443 without credentials, query strings or fragments.');
  }
  const hostname = url.hostname;
  if (isIP(hostname) || hostname.includes(':') || hostname.length > 253 || !hostname.includes('.') || hostname.endsWith('.') ||
      !hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) {
    throw new Error('Targets must use fully qualified DNS hostnames; IP literals and wildcards are unsupported.');
  }
  return url.href;
}

export function validateConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Configuration must be a JSON object.');
  for (const key of Object.keys(input)) if (!['schemaVersion', 'targets', 'dns', 'timeoutMs'].includes(key)) throw new Error(`Unknown configuration property: ${key}`);
  if (input.schemaVersion !== 1) throw new Error('Configuration schemaVersion must be 1.');
  if (!Array.isArray(input.targets) || input.targets.length < 1 || input.targets.length > 20) throw new Error('Configure between 1 and 20 explicit HTTPS targets.');
  const targets = input.targets.map(normalizeTarget);
  if (new Set(targets).size !== targets.length) throw new Error('Duplicate targets are not allowed.');
  const dns = input.dns ?? true, timeoutMs = input.timeoutMs ?? 10000;
  if (typeof dns !== 'boolean') throw new Error('dns must be true or false.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) throw new Error('timeoutMs must be an integer between 1000 and 30000.');
  return { schemaVersion: 1, targets, dns, timeoutMs };
}
