/** Exact root wire/canonical representation. Content hashes are never authority. */
import { createHash } from 'node:crypto';
import path from 'node:path';
import type { NativePublicationRecord } from './restrictedPartnerPublication.js';
export const nativeWireSchema = 'bridge-native-html-release/v1';
export const nativeDispatcher = 'scripts.publish_generic_html_direct';
export const publicationEffects = [
  'remote-staging-prepare',
  'remote-staging-upload',
  'remote-transaction',
] as const;
export const canonical = (v: unknown): string =>
  JSON.stringify(v, (_k, x) =>
    x && typeof x === 'object' && !Array.isArray(x)
      ? Object.fromEntries(
          Object.keys(x)
            .sort()
            .map((k) => [k, x[k]]),
        )
      : x,
  );
export const digest = (v: unknown) => createHash('sha256').update(canonical(v)).digest('hex');
const denied = (): never => {
  throw Error('NATIVE_ROOT_PROTOCOL_DENIED');
};
export function wireBinding(a: NativePublicationRecord) {
  const keys = [
    'nativeActionId',
    'actionRevision',
    'grantId',
    'grantRevision',
    'domainId',
    'principalId',
    'partnerId',
    'connectionId',
    'generation',
    'chatId',
    'eventId',
    'runId',
    'effectSlot',
    'epoch',
    'resourceFingerprint',
    'completedOutputSha256',
    'artifactSha256',
    'publisherBindingSha256',
    'artifactRelative',
  ] as const;
  const b = Object.fromEntries(keys.map((k) => [k, a[k]]));
  return { ...b, expiresAt: new Date(a.expiresAt).toISOString() };
}
export function publicMarker(b: Record<string, unknown>) {
  return {
    native_action_ref: digest({ domain: 'native-html-action/v1', action: b.nativeActionId }),
    binding_digest: digest({
      domain: 'native-html-binding/v1',
      binding: Object.fromEntries(
        Object.entries(b).filter(
          ([k]) => !['artifactRelative', 'artifactSha256', 'publisherBindingSha256'].includes(k),
        ),
      ),
    }),
  };
}
export function canonicalSidecar(b: Record<string, unknown>) {
  return Buffer.from(
    canonical({
      schema: nativeWireSchema,
      source: 'bluebubbles-connect',
      artifact_relative: b.artifactRelative,
      artifact_sha256: b.artifactSha256,
      publisher_binding_sha256: b.publisherBindingSha256,
      provenance: publicMarker(b),
    }) + '\n',
    'utf8',
  );
}
export function releaseId(b: Record<string, unknown>) {
  return digest({ domain: 'native-html-release/v1', binding: b });
}
export function releasePair(b: Record<string, unknown>) {
  if (
    typeof b.artifactRelative !== 'string' ||
    !/^core\/imessage\/imessage-[a-f0-9]{32}\.html$/.test(b.artifactRelative) ||
    typeof b.artifactSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(b.artifactSha256)
  )
    denied();
  const name = path.posix.basename(b.artifactRelative as string);
  return {
    [name]: b.artifactSha256,
    [name.slice(0, -5) + '.json']: createHash('sha256').update(canonicalSidecar(b)).digest('hex'),
  };
}
/** Python canonical helpers expect a list, never a caller object or its iteration order. */
export function orderedPair(wire: unknown, b: Record<string, unknown>): Array<[string, string]> {
  const pair = releasePair(b),
    names = Object.keys(pair);
  if (
    !wire ||
    typeof wire !== 'object' ||
    Array.isArray(wire) ||
    Object.keys(wire).length !== 2 ||
    Object.keys(wire).some((k) => !Object.hasOwn(pair, k)) ||
    names.some((k) => (wire as Record<string, unknown>)[k] !== pair[k])
  )
    denied();
  return names.map((k) => [k, pair[k] as string]);
}
/** JSON.parse alone silently accepts duplicate keys; reject them before materialization. */
export function parseNativeFrame(text: string): any {
  if (Buffer.byteLength(text) > 65535) throw Error('NATIVE_FRAME_LIMIT');
  let i = 0;
  const ws = () => {
    while (/[ \t\r\n]/.test(text[i] ?? '') && i < text.length) i++;
  };
  const string = () => {
    const start = i;
    if (text[i++] !== '"') denied();
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') return JSON.parse(text.slice(start, i)) as string;
      if (c === '\\') i++;
    }
    return denied();
  };
  const value = (depth: number): void => {
    if (depth > 32) denied();
    ws();
    const c = text[i];
    if (c === '"') {
      string();
      return;
    }
    if (c === '{') {
      i++;
      ws();
      const keys = new Set();
      if (text[i] === '}') {
        i++;
        return;
      }
      while (true) {
        ws();
        const k = string();
        if (keys.has(k)) denied();
        keys.add(k);
        ws();
        if (text[i++] !== ':') denied();
        value(depth + 1);
        ws();
        const end = text[i++];
        if (end === '}') return;
        if (end !== ',') denied();
      }
    } else if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') {
        i++;
        return;
      }
      while (true) {
        value(depth + 1);
        ws();
        const end = text[i++];
        if (end === ']') return;
        if (end !== ',') denied();
      }
    } else {
      const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        text.slice(i),
      );
      if (!match) denied();
      i += match![0].length;
    }
  };
  value(0);
  ws();
  if (i !== text.length) denied();
  return JSON.parse(text, (_k, v) => {
    if (typeof v === 'number' && !Number.isFinite(v)) denied();
    return v;
  });
}
