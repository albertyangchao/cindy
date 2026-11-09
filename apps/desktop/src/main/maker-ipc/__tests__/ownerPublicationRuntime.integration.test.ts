/** Test value (integration): production Main runtime + actual pinned Python
 * renderer/transaction builder, with only external SSH/SCP/HTTP effects synthetic.
 * D2/G1-02 had no owner native path; old tests cover the deferred restricted path.
 * Minimal regressions: non-owner record, altered stage, revoked owner, unknown
 * dispatch or mismatched public readback must never yield a successful receipt.
 * No real account paths or user media are read. No deployment/send occurs.
 */
import { afterAll, beforeAll, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { access, mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile, chmod } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createOwnerPublicationRuntime, type OwnerPublicationRoot, type OwnerPublicationTransport } from '../ownerPublicationRuntime.js';
import { canonical, digest, publicMarker, releaseId, releasePair, wireBinding } from '../restrictedPublicationProtocol.js';
import type { NativePublicationControl, NativePublicationRecord, NativePublisherRuntime } from '../restrictedPartnerPublication.js';

// The final Host patch also runs in a standalone Cindy checkout. Its integration
// tier must receive a separate synthetic/development Bridge source checkout.
const root = process.env.TEST_OWNER_PUBLICATION_BRIDGE_ROOT
  ? path.resolve(process.env.TEST_OWNER_PUBLICATION_BRIDGE_ROOT)
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../../../..');
const hash = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const text = 'Synthetic owner report\n\nThis is a non-personal example.';
let base: string;
let shared: Omit<OwnerPublicationRoot, 'dispatchRoot' | 'assertCurrent'>;
beforeAll(async () => {
  try { await access(path.join(root, 'bridge_core/publication_owner_render.py')); }
  catch {
    throw Error('Owner publication integration requires TEST_OWNER_PUBLICATION_BRIDGE_ROOT pointing to the matching development Bridge checkout; do not use a live runtime root.');
  }
  base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'owner-publication-test-')));
  const files: Record<string, string> = {};
  const gather = async (dir: string) => {
    for (const item of await readdir(path.join(root, dir), { withFileTypes: true })) {
      const name = dir + '/' + item.name;
      if (item.isDirectory() && item.name !== '__pycache__') await gather(name);
      else if (item.isFile() && (item.name.endsWith('.py') || dir.endsWith('runtime_contracts') && item.name.endsWith('.json')))
        files[name] = hash(await readFile(path.join(root, name)));
    }
  };
  await gather('bridge_core');
  for (const name of [
    'scripts/publish_worksheet_html.py', 'scripts/publish_generic_html_direct.py',
    'config/html_ui_contract.json', 'config/reserved_html_owners.json', 'config/artifact_publish_policy.json',
    'config/bridge_shell_builders.json', 'config/valerie_ivory_ui_contract.json', 'config/html_document_kinds.json',
  ]) files[name] = hash(await readFile(path.join(root, name)));
  const python = await realpath(execFileSync('python3', ['-I', '-c', 'import sys;print(sys.executable)'], { encoding: 'utf8' }).trim());
  shared = { root, publicOrigin: 'https://reports.boulangerievalerie.com', sourceIdentity: digest(files), files,
    python: { path: python, sha256: hash(await readFile(python)) } };
});
afterAll(async () => { if (base) await rm(base, { recursive: true, force: true }); });

async function fixture(fault?: 'unknown' | 'public-hash' | 'queued') {
  const dispatchRoot = path.join(base, randomUUID());
  await mkdir(dispatchRoot, { mode: 0o700 });
  let revoked = false;
  const current = () => { if (revoked) throw Error('OWNER_REVOKED'); };
  const pin: OwnerPublicationRoot = { ...shared, dispatchRoot, assertCurrent: async () => { current(); } };
  const calls: string[] = [];
  let record: NativePublicationRecord;
  const io: OwnerPublicationTransport = {
    async execute(executable, args, check) {
      check();
      const command = args.at(-1)!;
      calls.push(executable);
      if (fault === 'unknown' && calls.length === 1) throw Error('SIMULATED_EXTERNAL_UNKNOWN');
      if (command.includes('; then cat ')) {
        return { stdout: Buffer.from(canonical({ schema_version: 1, release_id: releaseId(wireBinding(record)),
          status: fault === 'queued' ? 'queued' : 'verified-after-public-readback', pair: releasePair(wireBinding(record)) })) };
      }
      if (command.startsWith('set -eu; test -f ')) return { stdout: Buffer.from(Object.values(releasePair(wireBinding(record))).join('\n') + '\n') };
      return { stdout: Buffer.alloc(0) };
    },
    async readback(url, check) {
      check(); calls.push('public-readback');
      expect(url).toBe(pin.publicOrigin + '/reports/' + record.artifactRelative + '?generic_release=' + releaseId(wireBinding(record)));
      return fault === 'public-hash' ? Buffer.from('wrong-public-bytes') : readFile(path.join(dispatchRoot, record.nativeActionId, path.posix.basename(record.artifactRelative)));
    },
  };
  const runtime: NativePublisherRuntime = createOwnerPublicationRuntime(pin, { effectCurrent: current, readCurrent: current }, io);
  record = {
    schema: 'native-publication-action/v1', authorityMode: 'owner-bridge/v1', ownerBindingSha256: 'c'.repeat(64), ownerBindingRevision: 1,
    nativeActionId: randomUUID(), actionRevision: 1, grantId: 'synthetic-grant', grantRevision: 1,
    domainId: 'synthetic-domain', principalId: 'synthetic-principal', partnerId: 'synthetic-partner',
    connectionId: 'synthetic-connection', generation: 'synthetic-generation', chatId: 'synthetic-chat', eventId: 'synthetic-event',
    runId: 'synthetic-run', effectSlot: 'synthetic-effect', epoch: 1, resourceFingerprint: 'a'.repeat(64),
    completedOutputSha256: hash(text), artifactSha256: null, publisherBindingSha256: null, artifactRelative: '',
    expiresAt: Date.now() + 60000, pluginId: 'synthetic-plugin', sourceOutputMessageId: 'synthetic-output', sourceInputSha256: 'b'.repeat(64),
    state: 'PREPARED_NO_REMOTE_EFFECT', stateRevision: 1, runtimeIdentity: runtime.identity, effects: [], publicUrl: null,
    receiptSha256: null, createdAt: Date.now(), publicNonPersonal: true, artifactApprovalSha256: null, audit: [],
  };
  record.artifactRelative = 'core/imessage/imessage-' + publicMarker(wireBinding(record)).binding_digest.slice(0, 32) + '.html';
  const control: NativePublicationControl = {
    async stageBind() {
      record = { ...record, ...await runtime.inspect(record) };
      record.artifactApprovalSha256 = digest(wireBinding(record));
      return record;
    },
    async beforeEffect(effect) {
      record = { ...record, state: 'DISPATCHING_UNKNOWN', effects: [...record.effects, effect] };
      return runtime.dispatch(record, effect);
    },
    async settle(receipt) { record = { ...record, state: 'APPLIED_VERIFIED', receiptSha256: receipt.receiptSha256 }; return record; },
  };
  return { runtime, pin, control, calls, get record() { return record; }, revoke() { revoked = true; } };
}

it('real canonical producer and Main dispatcher return a hash-bound receipt only after remote pair and public readback', async () => {
  const f = await fixture();
  await f.runtime.stage(f.record, text, f.control);
  const staged = f.record;
  const result = await f.runtime.apply(staged, f.control);
  expect(result.delivery_state).toBe('applied');
  expect(result.dispatcher).toBe('main.owner-bridge-publication/v1');
  expect(result.public_url_verified).toBe(true);
  expect(result.verifiedSha256).toBe(staged.artifactSha256);
  expect(f.calls).toEqual(['/usr/bin/ssh', '/usr/bin/scp', '/usr/bin/ssh', '/usr/bin/ssh', '/usr/bin/ssh', 'public-readback']);
  const sidecar = JSON.parse(await readFile(path.join(f.pin.dispatchRoot, staged.nativeActionId, path.posix.basename(staged.artifactRelative, '.html') + '.json'), 'utf8'));
  expect(sidecar.source).toBe('bluebubbles-connect');
  expect(sidecar.provenance).toEqual(publicMarker(wireBinding(staged)));
  expect(canonical(sidecar)).not.toContain('synthetic-principal');
  await expect(f.runtime.apply(staged, f.control)).rejects.toThrow();
  expect(f.calls).toHaveLength(6);
});

it.each(['public-hash', 'queued'] as const)('does not settle %s evidence as a successful publication', async (fault) => {
  const f = await fixture(fault);
  await f.runtime.stage(f.record, text, f.control);
  await expect(f.runtime.apply(f.record, f.control)).rejects.toThrow();
  expect(f.record.state).toBe('DISPATCHING_UNKNOWN');
  expect(f.record.receiptSha256).toBeNull();
});

it('unknown external effects retain the reservation and cannot be replayed', async () => {
  const f = await fixture('unknown');
  await f.runtime.stage(f.record, text, f.control);
  const staged = f.record;
  await expect(f.runtime.apply(staged, f.control)).rejects.toThrow();
  await expect(f.runtime.apply(staged, f.control)).rejects.toThrow();
  expect(f.calls).toHaveLength(1);
  expect(f.record.state).toBe('DISPATCHING_UNKNOWN');
});

it('rejects ordinary partner records, stage changes and revocation before remote dispatch', async () => {
  const f = await fixture();
  await expect(f.runtime.stage({ ...f.record, authorityMode: undefined }, text, f.control)).rejects.toThrow();
  await f.runtime.stage(f.record, text, f.control);
  const html = path.join(f.pin.dispatchRoot, f.record.nativeActionId, path.posix.basename(f.record.artifactRelative));
  await chmod(html, 0o600);
  await writeFile(html, 'altered');
  await expect(f.runtime.apply(f.record, f.control)).rejects.toThrow();
  expect(f.calls).toEqual([]);
  f.revoke();
  await expect(f.runtime.reconcile(f.record)).rejects.toThrow('OWNER_REVOKED');
});
