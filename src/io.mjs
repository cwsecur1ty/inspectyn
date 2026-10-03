import { open } from 'node:fs/promises';

export async function readBounded(path, limit) {
  const handle = await open(path, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Input must be a regular file.');
    if (stat.size > limit) throw new Error(`Input exceeds the ${limit}-byte limit.`);
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const result = await handle.read(buffer, length, buffer.length - length, null);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length > limit) throw new Error(`Input exceeds the ${limit}-byte limit.`);
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length));
  } finally { await handle.close(); }
}

export async function writeNewFile(path, text) {
  // 'wx' refuses existing files and symlinks.
  const handle = await open(path, 'wx', 0o600);
  try { await handle.writeFile(text, 'utf8'); } finally { await handle.close(); }
}
