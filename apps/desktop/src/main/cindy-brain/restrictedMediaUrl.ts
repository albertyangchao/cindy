/** Main-only URL leaf. No model schema, ambient credentials, redirect approval or retries. */
import { createHash } from 'node:crypto';
import { guardedOutboundFetch } from '../maker-host/outbound-fetch.js';
import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';
import { sniffRestrictedInputImage } from './restrictedMediaImage.js';
import type { MediaBinding, MediaPermit } from './restrictedMediaAdapter.js';
export type MediaUrlRole = 'input' | 'output';
export type MediaUrlGrant = {
  binding: MediaBinding;
  role: MediaUrlRole;
  sourceSha256: string;
  hosts: readonly string[];
  revision: number;
};
export type MediaUrlPorts = {
  authorize(permit: MediaPermit, url: string, role: MediaUrlRole): MediaUrlGrant;
  assertCurrent(permit: MediaPermit, grant: MediaUrlGrant): void;
  /** Existing durable stage reservation, never a new generation/effect on retry. */
  claim(permit: MediaPermit, sourceSha256: string, role: MediaUrlRole): Promise<boolean>;
  complete(permit: MediaPermit, sourceSha256: string, sha256: string): Promise<void>;
  unknown(permit: MediaPermit, sourceSha256: string): Promise<void>;
};
const sha = (x: string | Uint8Array) => createHash('sha256').update(x).digest('hex');
const denied = (): never => {
  throw Error('RESTRICTED_MEDIA_URL_DENIED');
};
const canonical = (b: MediaBinding) =>
  JSON.stringify(Object.entries(b).sort(([a], [c]) => a.localeCompare(c)));
export function createRestrictedMediaUrlLoader(ports: MediaUrlPorts) {
  return async (permit: MediaPermit, raw: string, role: MediaUrlRole) => {
    permit.assertCurrent();
    if (typeof raw !== 'string' || raw.length > 8192 || !['input', 'output'].includes(role))
      denied();
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      denied();
    }
    if (
      url!.protocol !== 'https:' ||
      url!.username ||
      url!.password ||
      url!.hash ||
      (url!.port && url!.port !== '443') ||
      url!.hostname.endsWith('.') ||
      !url!.hostname.includes('.') ||
      /[\[\]:]/.test(url!.hostname) ||
      /^\d+(\.\d+){3}$/.test(url!.hostname)
    )
      denied();
    const sourceSha256 = sha(raw),
      grant = ports.authorize(permit, raw, role);
    if (
      !grant ||
      grant.sourceSha256 !== sourceSha256 ||
      grant.role !== role ||
      canonical(grant.binding) !== canonical(permit.binding) ||
      !Number.isSafeInteger(grant.revision) ||
      grant.revision < 1 ||
      !grant.hosts.includes(url!.hostname)
    )
      denied();
    const frozen = Object.freeze({
      ...grant,
      binding: Object.freeze({ ...grant.binding }),
      hosts: Object.freeze([...grant.hosts]),
    });
    const controller = new AbortController();
    const signal = AbortSignal.any([permit.signal, controller.signal]);
    const current = () => {
      if (signal.aborted) denied();
      permit.assertCurrent();
      ports.assertCurrent(permit, frozen);
    };
    current();
    if (!(await ports.claim(permit, sourceSha256, role))) throw Error('RESTRICTED_MEDIA_URL_HELD');
    let responseBody: ReadableStream<Uint8Array> | null = null;
    let release: (() => Promise<void>) | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let abortRead: (() => void) | undefined;
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      current();
      const opened = await guardedOutboundFetch(
        url!.href,
        { method: 'GET', redirect: 'manual', signal, headers: {} },
        current,
        { targetUrl: url!.href, allowHttp: false, allowPrivateNetwork: false },
      );
      release = opened.release;
      const response = opened.response;
      responseBody = response.body;
      current();
      if (response.status !== 200 || !response.body) denied();
      const header = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
      if (!header?.startsWith('image/')) denied();
      const length = response.headers.get('content-length');
      if (length && (!/^\d+$/.test(length) || Number(length) > 8 * 1024 * 1024)) denied();
      reader = response.body!.getReader();
      const aborted = new Promise<never>((_, reject) => {
        abortRead = () => {
          void reader?.cancel().catch(() => {});
          reject(Error('RESTRICTED_MEDIA_URL_STOPPED'));
        };
        signal.addEventListener('abort', abortRead, { once: true });
        if (signal.aborted) abortRead();
      });
      const chunks: Uint8Array[] = [];
      let size = 0;
      for (;;) {
        const part = await Promise.race([reader.read(), aborted]);
        current();
        if (part.value) {
          size += part.value.byteLength;
          if (size > 8 * 1024 * 1024) denied();
          chunks.push(Uint8Array.from(part.value));
        }
        if (part.done) break;
      }
      const bytes = Buffer.concat(chunks);
      const mimeType = role === 'input' ? sniffRestrictedInputImage(bytes) : sniffMediaMime(bytes);
      if (!bytes.length || !mimeType?.startsWith('image/') || mimeType !== header) denied();
      current();
      const sha256 = sha(bytes);
      await ports.complete(permit, sourceSha256, sha256);
      current();
      return { bytes, mimeType: mimeType!, sha256, sourceSha256, binding: permit.binding, role };
    } catch {
      try {
        await ports.unknown(permit, sourceSha256);
      } finally {
        throw Error('RESTRICTED_MEDIA_URL_UNKNOWN');
      }
    } finally {
      clearTimeout(timer);
      if (abortRead) signal.removeEventListener('abort', abortRead);
      void reader?.cancel().catch(() => {});
      reader?.releaseLock();
      controller.abort();
      if (!reader) void responseBody?.cancel().catch(() => {});
      try {
        await release?.();
      } catch {
        /* release cannot expose provider errors */
      }
    }
  };
}
