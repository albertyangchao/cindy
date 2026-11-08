/** Security preflight uses actual SQLite and filesystem checks. No executable,
 * resident, OS census or source receipt is simulated as a positive control. */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { canonical, digest } from '../restrictedPublicationProtocol.js';
import {
  RestrictedPublicationResidentSource, readOriginalPublicationPeerReceipt, isOriginalPublicationSource,
  type PinnedPublicationResidentSource,
} from '../restrictedPublicationResidentSource.js';
import {
  RestrictedPublicationOwnerRegistry, readOriginalPublicationRegistrySeal, isOriginalPublicationRegistry,
} from '../restrictedPublicationOwnerRegistry.js';
import type { PublicationSourceBinding } from '../restrictedPublicationCISourceBroker.js';

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => { for (const release of cleanup.splice(0).reverse()) await release(); });
async function fixture() {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'original-source-preflight-')));
  cleanup.push(() => rm(root, { recursive: true, force: true }));
  const db = new Database(':memory:');
  cleanup.push(async () => db.close());
  db.exec('CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))');
  let live = true;
  const owner = () => { if (!live) throw Error('OWNER_CHANGED'); };
  const store = createRestrictedPartnerStore({ drizzle: drizzle(db) } as unknown as DbClient, owner);
  const expected: PublicationSourceBinding = { accountId: digest('account'), deviceId: digest('device'),
    bootId: 'test-boot', ownerEpoch: 1, generation: 'test-generation' };
  const python = path.join(root, 'not-executed');
  const profile: PinnedPublicationResidentSource = {
    root, files: {}, python: { path: python, sha256: digest('python') }, sourceDigest: digest('source'),
    runtimeDirectory: path.join(root, 'rendezvous'), owners: [{ instanceId: 'original-instance',
      ownerId: 'core.monitor.publish', sourceScope: 'RESIDENT_ORIGINAL_ENTRY',
      entryScript: 'scripts/publish_html_report.py', originalEntryScript: 'scripts/publish_html_report.py',
      originalRoot: root, originalArgv: [python, path.join(root, 'scripts/publish_html_report.py')],
      entryArgv: [python, '-I', '-B', path.join(root, 'scripts/publish_html_report.py')],
      originalBootstrapSha256: digest('bootstrap'), definitionDigest: digest('definition') }],
  };
  const start = (operationId = 'original-operation', p = profile, b = expected) =>
    RestrictedPublicationResidentSource.startOwned(store, 'plugin', operationId, p, b,
      () => { owner(); return { ...expected }; });
  const rows = () => db.prepare('SELECT payload,revision FROM plugin_task_requests ORDER BY id').all();
  return { root, db, store, expected, profile, start, rows, revoke: () => { live = false; } };
}

it('consumes the original operation and instance before source pin checks, without a peer fact', async () => {
  const f = await fixture();
  await expect(f.start()).rejects.toThrow('SOURCE_PROFILE');
  const values = f.rows().map(x => JSON.parse((x as { payload: string }).payload));
  expect(values).toHaveLength(2);
  expect(values.find(x => x.schema === 'publication-original-instance-claim/v1').scope).toBe('EXPECTED_INSTANCE_ONLY');
  const listener = values.find(x => x.schema === 'publication-original-owner-listener/v1');
  expect(listener.state).toBe('UNKNOWN');
  expect(listener.listenerPid).toBeNull();
  expect(listener.peers).toEqual([]);
});

it('preserves UNKNOWN and refuses the same operation on another boot or generation', async () => {
  const f = await fixture();
  await expect(f.start()).rejects.toThrow('SOURCE_PROFILE');
  const before = f.rows();
  f.expected.bootId = 'next-boot'; f.expected.generation = 'next-generation'; f.expected.ownerEpoch++;
  await expect(f.start()).rejects.toThrow('OPERATION_ALREADY_CLAIMED');
  expect(f.rows()).toEqual(before);
});

it('a replacement operation ID cannot resubmit the consumed original instance', async () => {
  const f = await fixture();
  await expect(f.start()).rejects.toThrow('SOURCE_PROFILE');
  const key = digest(['publication-original-instance-claim/v1', f.expected.deviceId, 'original-instance']);
  const before = await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key);
  await expect(f.start('replacement-operation')).rejects.toThrow('INSTANCE_ALREADY_CLAIMED');
  expect(await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key)).toEqual(before);
});

it.each(['pid', 'counters', 'receipt'])('rejects caller supplied %s before paths, claims or process startup', async field => {
  const f = await fixture();
  const extra = { ...f.profile, [field]: { state: 'LOADED', processId: 42 } };
  await expect(f.start('raw-facts', extra)).rejects.toThrow('SCHEMA');
  expect(f.rows()).toEqual([]);
});

it('retains the original 256 source-file ceiling on a complete oversize plan', async () => {
  const f = await fixture();
  const names = ['bridge_core/publication_owner_listener.py', 'bridge_core/publication_resident_source.py',
    'scripts/publish_html_report.py', ...Array.from({ length: 254 }, (_, i) => `source/${i}.py`)];
  f.profile.files = Object.fromEntries(names.map(name => [name, digest(name)]));
  expect(Object.keys(f.profile.files)).toHaveLength(257);
  await expect(f.start()).rejects.toThrow('SOURCE_PROFILE');
});

it('refuses changed Main owner before any durable claim or filesystem lookup', async () => {
  const f = await fixture(); f.revoke();
  await expect(f.start()).rejects.toThrow('OWNER_CHANGED');
  expect(f.rows()).toEqual([]);
});

it('duplicate expected instance IDs cannot create a listener', async () => {
  const f = await fixture();
  f.profile.owners = [f.profile.owners[0], structuredClone(f.profile.owners[0])];
  await expect(f.start()).rejects.toThrow('PROFILE');
  expect(f.rows()).toEqual([]);
});

it('JSON observations, prototypes and empty objects cannot become private peer or census seals', () => {
  const owner = Object.create(RestrictedPublicationResidentSource.prototype);
  const registry = Object.create(RestrictedPublicationOwnerRegistry.prototype);
  expect(isOriginalPublicationSource(owner)).toBe(false);
  expect(isOriginalPublicationRegistry(registry)).toBe(false);
  for (const value of [{}, { state: 'LOADED', processId: 42 }, Object.freeze(Object.create(null))]) {
    expect(() => readOriginalPublicationPeerReceipt(value, owner)).toThrow('PRIVATE_RECEIPT_REQUIRED');
    expect(() => readOriginalPublicationRegistrySeal(value, registry)).toThrow('PRIVATE_SEAL_REQUIRED');
  }
});

it('durable encoding preserves every pin and reconstructs every full observation within the unchanged row cap', () => {
  // Explicit serialization fixture, not an original source/OS/runtime proof.
  const files = Object.fromEntries(Array.from({ length: 38 }, (_, i) =>
    [`monitor/long-reviewed-import-path-${i}/publication_original_effect_boundary.py`, digest(i)]));
  const peers = Array.from({ length: 7 }, (_, i) => ({ instanceId: `service-${i}`,
    peerId: `peer-${i}`, identity: digest(i), revision: 2, phase: 'LOADED',
    observation: { instanceId: `service-${i}`, files, process: { processId: 100 + i },
      observation: { state: 'LOADED', activeOperations: 0, unknownOperations: 0, fenceRevision: 0,
        probe: { schema: 'serialization-fixture-only', files, nonce: digest(i), arbitraryRetainedValue: [i, null, 'exact'] } } } }));
  const ledger = { schema: 'serialization-fixture-only', peers };
  expect(Buffer.byteLength(JSON.stringify(ledger))).toBeGreaterThan(65536);
  const fixtureOwner = { profile: { files }, ledger };
  expect(isOriginalPublicationSource(fixtureOwner)).toBe(false);
  const payload = Reflect.apply(Reflect.get(RestrictedPublicationResidentSource.prototype, 'payload'), fixtureOwner, []);
  if (typeof payload !== 'string') throw Error('SERIALIZATION_RESULT_NOT_STRING');
  expect(Buffer.byteLength(payload)).toBeLessThanOrEqual(65536);
  const saved = JSON.parse(payload);
  expect(saved.pinnedFiles).toEqual(files);
  expect(saved.pinnedFilesSha256).toBe(digest(files));
  expect(saved.peers).toHaveLength(7);
  for (let i = 0; i < peers.length; i++) {
    const stored = saved.peers[i];
    const { filesRef, ...observed } = stored.observation;
    expect(filesRef).toBe(saved.pinnedFilesSha256);
    const proof = observed.observation.probe;
    expect(proof.filesRef).toBe(saved.pinnedFilesSha256);
    const probe = { ...proof.data, files: saved.pinnedFiles };
    expect(digest(probe)).toBe(proof.sha256);
    const restored = { ...observed, files: saved.pinnedFiles, observation: { ...observed.observation, probe } };
    expect(restored).toEqual(peers[i].observation);
    expect(digest(restored)).toBe(stored.observationSha256);
  }
});

it('a fresh operation and fresh instance cannot wash a prior runtime UNKNOWN', async () => {
  const f = await fixture();
  await expect(f.start()).rejects.toThrow('SOURCE_PROFILE');
  const before = f.rows();
  const next = structuredClone(f.profile);
  next.owners[0].instanceId = 'fresh-original-instance';
  f.expected.generation = 'fresh-generation'; f.expected.ownerEpoch++;
  await expect(f.start('fresh-operation', next)).rejects.toThrow('PRIOR_POLICY_CUTOVER_UNKNOWN');
  expect(f.rows()).toEqual(before);
});

it.each(['UNKNOWN', 'PREPARED'])('an incomplete actual cutover journal state %s blocks a new listener realm', async state => {
  const f = await fixture();
  const key = digest(['cutover-journal-negative', state]);
  expect(await f.store.compareAndSwapConsumerGuardReceipt('plugin', f.expected.accountId, key, undefined,
    canonical({ schema: 'publication-original-policy-cutover/v1', state }))).toBe(true);
  const before = f.rows();
  await expect(f.start()).rejects.toThrow('PRIOR_POLICY_CUTOVER_UNKNOWN');
  expect(f.rows()).toEqual(before);
});

it('plain or copied terminal handles cannot acquire policy cutover authority', async () => {
  const source = Object.create(RestrictedPublicationResidentSource.prototype) as RestrictedPublicationResidentSource;
  const registry = Object.create(RestrictedPublicationOwnerRegistry.prototype) as RestrictedPublicationOwnerRegistry;
  const f = await fixture();
  for (const handle of [{}, { state: 'POLICY_PREPARED', revision: 2 }, Object.freeze(Object.create(null))]) {
    expect(() => source.retainedPolicyProfile(handle)).toThrow('PRIVATE_CUTOVER_REQUIRED');
    await expect(source.rotatePreparedPolicy(handle, f.profile, {}, registry, {})).rejects.toThrow('PRIVATE_CUTOVER_REQUIRED');
    await expect(source.verifyPreparedPolicy(handle, {}, registry, {})).rejects.toThrow('PRIVATE_POLICY_PREPARATION_REQUIRED');
  }
  expect(f.rows()).toEqual([]);
});

it.each([
  { terminal: false, nonce: null, accepted: false },
  { terminal: false, nonce: digest('next'), accepted: true },
  { terminal: true, nonce: null, accepted: true },
  { terminal: true, nonce: digest('next'), accepted: false },
])('wire parser confines terminal null nonce to terminal=%s', ({ terminal, nonce, accepted }) => {
  // Serialization-only parser fixture. It is deliberately not a branded source
  // and cannot create an original peer, EOF, DRAINED or completed rotate proof.
  let resolved: unknown, refused: unknown;
  const timer = setTimeout(() => {}, 1000);
  const expected = { accountId: digest('a'), deviceId: digest('d'), bootId: 'fixture', ownerEpoch: 1, generation: 'g' };
  const owner = { inputBytes: 0, buffer: Buffer.alloc(0), sessionId: digest('session'), operationId: 'fixture',
    expected, sequence: 0, nextNonce: digest('previous'), terminalFrameReceived: false,
    pending: { seq: 1, terminal, timer, resolve: (value: unknown) => { resolved = value; } },
    rejectPending: (code: string) => { refused = code; clearTimeout(timer); } };
  const result = { state: 'POLICY_PREPARED' };
  Reflect.apply(Reflect.get(RestrictedPublicationResidentSource.prototype, 'receive'), owner, [Buffer.from(canonical({
    schema: 'resident-owner-listener/v1', sessionId: owner.sessionId, operationId: owner.operationId,
    binding: expected, seq: 1, nextNonce: nonce, ok: true, code: null, result,
  }) + '\n')]);
  clearTimeout(timer);
  expect(isOriginalPublicationSource(owner)).toBe(false);
  expect(resolved).toEqual(accepted ? result : undefined);
  expect(refused).toEqual(accepted ? undefined : 'FRAME_INVALID');
  expect(owner.terminalFrameReceived).toBe(accepted && terminal);
});

it.each([
  ['core-jit.persistent-bridge-pool', 'persistent-pool', 'sync-runner-pools.py'],
  ['core-jit.bridge-jit-controller', 'jit-controller', 'start-approved-jit-runner.sh'],
  ['core-jit.bridge-jit-dispatcher', 'jit-dispatcher', 'jit-deploy-dispatcher.sh'],
])('keeps the real runtime-copy path for %s before original pin verification', async (ownerId, role, filename) => {
  const f = await fixture(), owner = f.profile.owners[0];
  Object.assign(owner, { ownerId, sourceScope: 'REGISTERED_CI_PRODUCER',
    entryScript: 'bridge_core/publication_ci_producer.py', originalEntryScript: filename,
    originalArgv: ['/bin/bash', path.join(f.root, filename)],
    entryArgv: [f.profile.python.path, '-I', '-B', path.join(f.root, 'bridge_core/publication_ci_producer.py'), role] });
  f.profile.files = { ['macmini-jit-controller/' + filename]: owner.originalBootstrapSha256,
    'macmini-jit-controller/publication_ci_owner.py': digest('helper'),
    'bridge_core/publication_ci_producer.py': digest('producer') };
  // The constructor must accept actual layout metadata, then fail on missing
  // real source pins. This is not a successful original peer or process start.
  await expect(f.start()).rejects.toThrow('SOURCE_PROFILE');
  expect(f.rows()).toHaveLength(2);
  expect(f.rows().map(x => JSON.parse((x as { payload: string }).payload))
    .find(x => x.schema === 'publication-original-owner-listener/v1').listenerPid).toBeNull();
});

it('a runtime-copy path never permits a different CI role or canonical bootstrap hash', async () => {
  const f = await fixture(), owner = f.profile.owners[0];
  const entry = 'bridge_core/publication_ci_producer.py';
  Object.assign(owner, { ownerId: 'core-jit.bridge-jit-controller', sourceScope: 'REGISTERED_CI_PRODUCER',
    entryScript: entry, originalEntryScript: 'start-approved-jit-runner.sh',
    originalArgv: ['/bin/bash', path.join(f.root, 'start-approved-jit-runner.sh')],
    entryArgv: [f.profile.python.path, '-I', '-B', path.join(f.root, entry), 'jit-dispatcher'] });
  f.profile.files = { 'macmini-jit-controller/start-approved-jit-runner.sh': owner.originalBootstrapSha256,
    'macmini-jit-controller/publication_ci_owner.py': digest('helper'), [entry]: digest('producer') };
  await expect(f.start()).rejects.toThrow('PROFILE');
  owner.entryArgv[4] = 'jit-controller';
  f.profile.files = { ...f.profile.files, 'macmini-jit-controller/start-approved-jit-runner.sh': digest('foreign') };
  await expect(f.start()).rejects.toThrow('PROFILE');
  expect(f.rows()).toEqual([]);
});
