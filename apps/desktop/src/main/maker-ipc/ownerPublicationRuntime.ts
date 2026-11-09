/** D2 owner-only canonical Bridge runtime. The Main action owns every effect.
 * The Python producer returns pure candidates; stdout, hashes and JSON never
 * grant a release. Existing restricted publication/coverage paths are unchanged.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import type {
  NativePublisherRuntime,
  NativePublicationRecord,
  NativePublicationReceipt,
  PublicationEffect,
} from './restrictedPartnerPublication.js';
import {
  canonical, canonicalSidecar, digest, nativeWireSchema,
  orderedPair, publicMarker, publicationEffects, releaseId, releasePair, wireBinding,
} from './restrictedPublicationProtocol.js';

export interface OwnerPublicationRoot {
  root: string;
  dispatchRoot: string;
  publicOrigin: string;
  sourceIdentity: string;
  files: Record<string, string>;
  python: { path: string; sha256: string };
  /** Main config/checkout resolver, never supplied by IPC or the plugin. */
  assertCurrent(): Promise<void>;
}
export interface OwnerPublicationTransport {
  execute(executable: '/usr/bin/ssh' | '/usr/bin/scp', args: string[], current: () => void): Promise<{ stdout: Buffer }>;
  readback(url: string, current: () => void): Promise<Buffer>;
}
const producerSchema = 'owner-publication-producer/v1';
export const ownerPublicationDispatcher = 'main.owner-bridge-publication/v1';
const producer = 'import os,runpy,sys;sys.pycache_prefix=os.devnull;sys.path.insert(0,sys.argv[1]);runpy.run_module("bridge_core.publication_owner_render",run_name="__main__")';
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const denied = (): never => { throw Error('OWNER_PUBLICATION_RUNTIME_DENIED'); };
const requireThat: (value: unknown) => asserts value = (value) => { if (!value) denied(); };
const requiredSources = [
  'bridge_core/publication_owner_render.py', 'bridge_core/native_html_release.py',
  'bridge_core/html_templates.py', 'bridge_core/html_contract.py',
  'bridge_core/report_secret_gate.py', 'bridge_core/report_publish_queue.py',
  'scripts/publish_worksheet_html.py', 'scripts/publish_generic_html_direct.py',
  'config/html_ui_contract.json', 'config/reserved_html_owners.json',
  'config/artifact_publish_policy.json', 'config/bridge_shell_builders.json',
  'config/valerie_ivory_ui_contract.json', 'config/html_document_kinds.json',
];

function processBytes(executable: string, args: string[], current: () => void,
  input?: unknown, cwd?: string, limit = 65536, timeout = 120000): Promise<{ stdout: Buffer }> {
  current();
  return new Promise((resolve, reject) => {
    let ended = false, size = 0;
    const chunks: Buffer[] = [];
    const child = spawn(executable, args, {
      ...(cwd ? { cwd, env: { PATH: '/usr/bin:/bin', LANG: 'en_US.UTF-8', PYTHONDONTWRITEBYTECODE: '1' } } : {}),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const finish = (error?: unknown) => {
      if (ended) return;
      ended = true;
      clearTimeout(timer);
      child.stdin.destroy();
      if (error) {
        child.kill();
        reject(Error('OWNER_PUBLICATION_OPERATION_UNKNOWN'));
      } else {
        try { current(); resolve({ stdout: Buffer.concat(chunks) }); }
        catch { reject(Error('OWNER_PUBLICATION_OPERATION_UNKNOWN')); }
      }
    };
    const timer = setTimeout(() => finish(Error('TIMEOUT')), timeout);
    child.stdin.on('error', () => {});
    child.stderr.on('data', () => {});
    child.stdout.on('data', (chunk: Buffer) => {
      try { current(); } catch (error) { finish(error); return; }
      size += chunk.length;
      if (size > limit) finish(Error('LIMIT')); else chunks.push(chunk);
    });
    child.on('error', finish);
    child.on('close', (code) => finish(code === 0 ? undefined : Error('EXIT')));
    child.stdin.end(input === undefined ? undefined : canonical(input));
  });
}
const transport: OwnerPublicationTransport = {
  execute: (executable, args, current) => processBytes(executable, args, current),
  async readback(url, current) {
    current();
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 15000);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      const result = await fetch(url, { redirect: 'error', signal: abort.signal });
      current();
      requireThat(result.status === 200 && result.body);
      reader = result.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      while (true) {
        current();
        const part = await reader.read();
        current();
        if (part.done) break;
        size += part.value.byteLength;
        requireThat(size <= 512 * 1024);
        chunks.push(part.value);
      }
      return Buffer.concat(chunks);
    } finally { clearTimeout(timer); void reader?.cancel().catch(() => {}); }
  },
};

async function readFixed(root: string, relative: string, limit = 12 * 1024 * 1024) {
  requireThat(relative && !relative.includes('\\') && !relative.split('/').some(x => !x || x === '.' || x === '..'));
  requireThat(await realpath(root) === root);
  let parent = root;
  for (const part of ['', ...relative.split('/').slice(0, -1)]) {
    if (part) parent = path.join(parent, part);
    const st = await lstat(parent);
    requireThat(st.isDirectory() && !st.isSymbolicLink() && !(st.mode & 0o022) && (!process.getuid || st.uid === process.getuid()));
  }
  const file = await open(path.join(root, relative), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    requireThat(before.isFile() && before.nlink === 1 && !(before.mode & 0o022) && before.size <= limit && (!process.getuid || before.uid === process.getuid()));
    const bytes = await file.readFile(), after = await file.stat();
    requireThat(before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs);
    return bytes;
  } finally { await file.close(); }
}
async function writeNew(root: string, name: string, bytes: Buffer) {
  const file = await open(path.join(root, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o400);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  requireThat(hash(await readFixed(root, name, 1024 * 1024)) === hash(bytes));
}

/** Called only by Main's owner action factory with a resolver-owned root. */
export function createOwnerPublicationRuntime(
  pin: OwnerPublicationRoot,
  guards: { effectCurrent(): void; readCurrent(): void },
  io: OwnerPublicationTransport = transport,
): NativePublisherRuntime {
  requireThat(pin && typeof pin.assertCurrent === 'function' && path.isAbsolute(pin.root) && path.isAbsolute(pin.dispatchRoot));
  requireThat(pin.publicOrigin === 'https://reports.boulangerievalerie.com' && /^[a-f0-9]{64}$/.test(pin.sourceIdentity));
  requireThat(path.isAbsolute(pin.python.path) && /^[a-f0-9]{64}$/.test(pin.python.sha256));
  requireThat(requiredSources.every(name => /^[a-f0-9]{64}$/.test(pin.files[name] ?? '')));
  const files = Object.freeze({ ...pin.files }), python = Object.freeze({ ...pin.python });
  const definition = canonical([pin.root, pin.dispatchRoot, pin.publicOrigin, pin.sourceIdentity, files, python]);
  const identity = digest(['owner-bridge/v1', definition]);
  const current = (readonly = false) => (readonly ? guards.readCurrent : guards.effectCurrent)();
  const verify = async () => {
    current(true);
    requireThat(definition === canonical([pin.root, pin.dispatchRoot, pin.publicOrigin, pin.sourceIdentity, pin.files, pin.python]));
    await pin.assertCurrent();
    for (const [name, expected] of Object.entries(files)) {
      requireThat(/^[a-f0-9]{64}$/.test(expected) && hash(await readFixed(pin.root, name)) === expected);
      current(true);
    }
    requireThat(await realpath(python.path) === python.path && hash(await readFile(python.path)) === python.sha256);
    requireThat(await realpath(pin.dispatchRoot) === pin.dispatchRoot);
    const st = await lstat(pin.dispatchRoot);
    requireThat(st.isDirectory() && !st.isSymbolicLink() && !(st.mode & 0o077) && (!process.getuid || st.uid === process.getuid()));
    current(true);
  };
  const action = (a: NativePublicationRecord) => {
    current(true);
    requireThat(a.authorityMode === 'owner-bridge/v1' && a.runtimeIdentity === identity && /^[a-f0-9]{64}$/.test(a.ownerBindingSha256 ?? '') && Number.isSafeInteger(a.ownerBindingRevision) && a.ownerBindingRevision! > 0);
    requireThat(/^[a-f0-9-]{36}$/.test(a.nativeActionId) && a.actionRevision === 1 && /^[a-f0-9]{64}$/.test(a.completedOutputSha256));
    const marker = publicMarker(wireBinding(a));
    requireThat(a.artifactRelative === 'core/imessage/imessage-' + marker.binding_digest.slice(0, 32) + '.html');
    return path.join(pin.dispatchRoot, a.nativeActionId);
  };
  const pure = async (a: NativePublicationRecord, operation: 'render' | 'commands', text?: string, readonly = false) => {
    action(a);
    await verify();
    current(readonly);
    const input = { operation, binding: wireBinding(a), ...(operation === 'render' ? { text } : {}) };
    requireThat(Buffer.byteLength(canonical(input)) <= 65536);
    const result = await processBytes(python.path, ['-I', '-S', '-B', '-c', producer, pin.root], () => current(readonly), input, pin.root, 1024 * 1024, 10000);
    await pin.assertCurrent();
    current(readonly);
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout));
    requireThat(value?.schema === producerSchema);
    return value;
  };
  const candidate = async (a: NativePublicationRecord) => {
    const dir = action(a), raw = await readFixed(dir, 'render.json', 65536);
    current(true);
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    const html = await readFixed(dir, path.posix.basename(a.artifactRelative), 512 * 1024);
    current(true);
    requireThat(value.schema === producerSchema && value.artifactRelative === a.artifactRelative && value.completedOutputSha256 === a.completedOutputSha256 && value.artifactSha256 === hash(html));
    requireThat(canonical(value.publicMarker) === canonical(publicMarker(wireBinding(a))));
    requireThat(value.publisherMetadata?.schema === producerSchema && value.publisherMetadata.source === 'bluebubbles-connect' && value.publisherMetadata.authority_mode === 'owner-bridge/v1');
    requireThat(value.publisherMetadata.sha256 === value.artifactSha256 && value.publisherMetadata.completed_output_sha256 === a.completedOutputSha256 && value.publisherMetadata.artifact_relative === a.artifactRelative);
    requireThat(canonical(value.publisherMetadata.provenance) === canonical(value.publicMarker) && digest(value.publisherMetadata) === value.publisherBindingSha256);
    return { value, html, dir };
  };
  const inspect = async (a: NativePublicationRecord) => {
    await verify();
    const { value } = await candidate(a);
    return { artifactSha256: value.artifactSha256 as string, publisherBindingSha256: value.publisherBindingSha256 as string, artifactRelative: a.artifactRelative, completedOutputSha256: a.completedOutputSha256 };
  };
  const commandPlan = async (a: NativePublicationRecord, readonly = false) => {
    const value = await pure(a, 'commands', undefined, readonly), b = wireBinding(a);
    requireThat(typeof value.host === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.host));
    requireThat(value.releaseId === releaseId(b) && value.publicUrl === pin.publicOrigin + '/reports/' + a.artifactRelative && canonical(value.orderedPair) === canonical(orderedPair(releasePair(b), b)));
    requireThat(['bootstrap', 'upload', 'transaction', 'receipt', 'verify'].every(k => typeof value[k] === 'string' && value[k].length > 0 && Buffer.byteLength(value[k]) <= 65536));
    requireThat(value.upload === '/var/lib/bridge-generic-html-publish/staging/' + releaseId(b) + '/');
    return value;
  };
  const attempted = new Set<string>(), dispatched = new Set<string>(), completed = new Map<string, PublicationEffect[]>();
  const observe = async (a: NativePublicationRecord): Promise<NativePublicationReceipt> => {
    const plan = await commandPlan(a, true), b = wireBinding(a), pair = releasePair(b);
    const check = guards.readCurrent;
    const receipt = await io.execute('/usr/bin/ssh', ['-o', 'BatchMode=yes', plan.host, plan.receipt], check);
    check();
    const expected = { schema_version: 1, release_id: releaseId(b), status: 'verified-after-public-readback', pair };
    requireThat(canonical(JSON.parse(receipt.stdout.toString('utf8'))) === canonical(expected));
    const observed = await io.execute('/usr/bin/ssh', ['-o', 'BatchMode=yes', plan.host, plan.verify], check);
    check();
    requireThat(canonical(observed.stdout.toString('utf8').trim().split('\n')) === canonical(orderedPair(pair, b).map(([, sha]) => sha)));
    const bytes = await io.readback(plan.publicUrl + '?generic_release=' + releaseId(b), check);
    check();
    requireThat(hash(bytes) === a.artifactSha256);
    await pin.assertCurrent();
    check();
    const raw = {
      schema: nativeWireSchema, nativeActionId: a.nativeActionId, actionRevision: a.actionRevision,
      grantId: a.grantId, grantRevision: a.grantRevision, completedOutputSha256: a.completedOutputSha256,
      artifactSha256: a.artifactSha256!, publisherBindingSha256: a.publisherBindingSha256!, artifactRelative: a.artifactRelative,
      dispatcher: ownerPublicationDispatcher, delivery_state: 'applied' as const, remoteReleaseId: releaseId(b),
      verifiedSha256: a.artifactSha256!, public_url_verified: true, observedAt: new Date().toISOString(),
    };
    return { ...raw, receiptSha256: digest(raw) };
  };
  return Object.freeze({
    identity, publicOrigin: pin.publicOrigin, dispatcher: ownerPublicationDispatcher,
    sourceRoot: pin.root, sourceIdentity: pin.sourceIdentity,
    verify, inspect,
    async stage(a, text, control) {
      current();
      requireThat(a.state === 'PREPARED_NO_REMOTE_EFFECT' && a.effects.length === 0 && a.artifactSha256 === null && a.publisherBindingSha256 === null && hash(text) === a.completedOutputSha256);
      const value = await pure(a, 'render', text);
      requireThat(typeof value.htmlBase64 === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(value.htmlBase64));
      const html = Buffer.from(value.htmlBase64, 'base64');
      requireThat(html.length > 0 && html.length <= 512 * 1024 && html.toString('base64') === value.htmlBase64 && hash(html) === value.artifactSha256);
      const dir = action(a);
      current();
      await mkdir(dir, { mode: 0o700 });
      current();
      await writeNew(dir, path.posix.basename(a.artifactRelative), html);
      current();
      const { htmlBase64: _bytes, ...metadata } = value;
      await writeNew(dir, 'render.json', Buffer.from(canonical(metadata)));
      current();
      await candidate(a);
      const approved = await control.stageBind();
      current();
      action(approved);
      requireThat(approved.artifactSha256 === value.artifactSha256 && approved.publisherBindingSha256 === value.publisherBindingSha256 && approved.artifactApprovalSha256 === digest(wireBinding(approved)));
      await writeNew(dir, path.posix.basename(a.artifactRelative, '.html') + '.json', canonicalSidecar(wireBinding(approved)));
      current();
    },
    async apply(a, control) {
      action(a);
      requireThat(a.state === 'PREPARED_NO_REMOTE_EFFECT' && a.effects.length === 0 && !attempted.has(a.nativeActionId));
      attempted.add(a.nativeActionId);
      for (const effect of publicationEffects) {
        current();
        await control.beforeEffect(effect);
        current();
      }
      requireThat(canonical(completed.get(a.nativeActionId)) === canonical(publicationEffects));
      const receipt = await observe(a);
      current();
      await control.settle(receipt);
      current();
      return receipt;
    },
    reconcile: observe,
    async dispatch(a, effect) {
      current();
      action(a);
      const prior = completed.get(a.nativeActionId) ?? [];
      requireThat(attempted.has(a.nativeActionId) && effect === publicationEffects[prior.length] && a.state === 'DISPATCHING_UNKNOWN' && a.effects.length === prior.length + 1 && a.effects.at(-1) === effect);
      const dispatchKey = a.nativeActionId + ':' + effect;
      requireThat(!dispatched.has(dispatchKey));
      // Reserve before the first await. A timeout or racing callback never
      // creates permission to repeat this effect in the current Main runtime.
      dispatched.add(dispatchKey);
      requireThat(a.artifactApprovalSha256 === digest(wireBinding(a)));
      const { value, dir } = await candidate(a);
      requireThat(value.artifactSha256 === a.artifactSha256 && value.publisherBindingSha256 === a.publisherBindingSha256);
      const plan = await commandPlan(a), pair = orderedPair(releasePair(wireBinding(a)), wireBinding(a));
      for (const [name, expected] of pair) {
        requireThat(hash(await readFixed(dir, name, 512 * 1024)) === expected);
        current();
      }
      await pin.assertCurrent();
      current();
      if (effect === 'remote-staging-prepare') await io.execute('/usr/bin/ssh', ['-o', 'BatchMode=yes', plan.host, plan.bootstrap], guards.effectCurrent);
      else if (effect === 'remote-staging-upload') await io.execute('/usr/bin/scp', ['-o', 'BatchMode=yes', ...pair.map(([name]) => path.join(dir, name)), plan.host + ':' + plan.upload], guards.effectCurrent);
      else await io.execute('/usr/bin/ssh', ['-o', 'BatchMode=yes', plan.host, plan.transaction], guards.effectCurrent);
      current();
      prior.push(effect);
      completed.set(a.nativeActionId, prior);
      return { dispatched: true };
    },
  } satisfies NativePublisherRuntime);
}
