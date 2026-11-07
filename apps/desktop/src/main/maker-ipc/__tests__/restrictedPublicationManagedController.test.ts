/** tier: unit. Real account SQLite and private filesystem release installs; no app/service/model/network. */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, realpath, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import {
  ManagedPublicationController,
  readManagedLifecycleReceipt,
  type PublisherReleaseSource,
} from '../restrictedPublicationManagedController.js';
import { supportedPublicationRoot } from '../restrictedPublicationCaller.js';
const sha = (v: string) => createHash('sha256').update(v).digest('hex');
const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0)) await f();
});
async function fixture() {
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'managed-release-')));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const sqlite = new Database(':memory:');
  cleanup.push(async () => sqlite.close());
  sqlite.exec(
    'CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))',
  );
  sqlite
    .prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)')
    .run('old', 'plugin', 'target', 'restricted:old', 'old', 'old', '{"state":"UNKNOWN"}', 2, 1);
  let current = true;
  const owner = () => {
    if (!current) throw Error('OWNER_REVOKED');
  };
  const store = createRestrictedPartnerStore(
    { drizzle: drizzle(sqlite) } as unknown as DbClient,
    owner,
  );
  const account = sha('synthetic-account'),
    device = sha('synthetic-device');
  const controller = new ManagedPublicationController(store, 'plugin', account, device, owner);
  const root = path.join(dir, 'source'),
    releases = path.join(dir, 'releases'),
    binary = path.join(dir, 'bin');
  for (const p of [root, releases, binary]) await mkdir(p, { mode: 0o700 });
  const files: Record<string, string> = {};
  for (const relative of [
    'bridge_core/publication_consumer_controller.py',
    'scripts/publish_generic_html_direct.py',
  ]) {
    const value = '# synthetic fixture source, not production-ready';
    await mkdir(path.dirname(path.join(root, relative)), { recursive: true, mode: 0o700 });
    await writeFile(path.join(root, relative), value, { mode: 0o600 });
    files[relative] = sha(value);
  }
  const python = path.join(binary, 'synthetic-interpreter');
  await writeFile(python, 'synthetic interpreter not executed', { mode: 0o600 });
  const source: PublisherReleaseSource = {
    sourceRoot: root,
    releasesRoot: releases,
    files,
    python: { path: python, sha256: sha('synthetic interpreter not executed') },
  };
  return {
    controller,
    source,
    sqlite,
    store,
    account,
    dir,
    owner,
    revokeOwner: () => {
      current = false;
    },
    preserved: () =>
      expect(
        sqlite.prepare('SELECT payload,revision FROM plugin_task_requests WHERE id=?').get('old'),
      ).toEqual({ payload: '{"state":"UNKNOWN"}', revision: 2 }),
  };
}
it('installs exact immutable release, switches its owned entry, revokes before subsequent use, never asserts external coverage', async () => {
  const f = await fixture();
  const r = await f.controller.install(f.source, 'g1');
  expect(await readFile(path.join(r.root, 'scripts/publish_generic_html_direct.py'), 'utf8')).toBe(
    '# synthetic fixture source, not production-ready',
  );
  await f.controller.switchEntry('g1');
  f.controller.assertCurrent(r.root);
  expect((await f.controller.inspect()).runtimeCoverage).toBe('UNKNOWN');
  expect(supportedPublicationRoot).toBeUndefined();
  const revocation = f.controller.revoke();
  expect(() => f.controller.assertCurrent(r.root)).toThrow('REVOKED');
  await revocation;
  await f.controller.drain(20);
  await expect(f.controller.install(f.source, 'g1')).rejects.toThrow('GENERATION');
  f.preserved();
});
it('restart never inherits active entries; rollback installs a new generation instead of reviving old state', async () => {
  const f = await fixture();
  const r = await f.controller.install(f.source, 'g1');
  await f.controller.switchEntry('g1');
  const restarted = new ManagedPublicationController(
    f.store,
    'plugin',
    f.account,
    sha('synthetic-device'),
    f.owner,
  );
  expect((await restarted.inspect()).state).toBe('UNKNOWN');
  expect(() => restarted.assertCurrent(r.root)).toThrow('REVOKED');
  await expect(restarted.revoke()).rejects.toThrow('FOREIGN_OWNER_HELD');
  f.controller.assertCurrent(r.root); // a second instance cannot steal the still-live owner
  await f.controller.revoke();
  await f.controller.drain(20);
  const next = await restarted.install(f.source, 'g2');
  expect(next.root).not.toBe(r.root);
  await restarted.switchEntry('g2');
  f.preserved();
});
it('source drift or symlink cannot produce an installed receipt and does not delete failed evidence', async () => {
  const f = await fixture();
  await writeFile(
    path.join(f.source.sourceRoot, 'scripts/publish_generic_html_direct.py'),
    'drift',
    { mode: 0o600 },
  );
  await expect(f.controller.install(f.source, 'bad')).rejects.toThrow('SOURCE_DRIFT');
  expect((await f.controller.inspect()).state).toBe('UNKNOWN');
  const g = await fixture();
  const linked = path.join(g.dir, 'linked');
  await symlink(g.source.sourceRoot, linked);
  await expect(g.controller.install({ ...g.source, sourceRoot: linked }, 'bad')).rejects.toThrow(
    'PATH',
  );
  g.preserved();
  f.preserved();
});
it('free JSON job and revoked owner cannot launch any child or manufacture controller coverage', async () => {
  const f = await fixture();
  await f.controller.install(f.source, 'g1');
  await f.controller.switchEntry('g1');
  await expect(
    f.controller.prepareOwnedChild({ metadata: { accountScopeRef: f.account } } as any, f.source, {
      operation: 'stage',
      artifacts: f.dir,
      queue: f.dir,
    }),
  ).rejects.toThrow('LAUNCH');
  expect((await f.controller.inspect()).ownedJobs).toBe(0);
  f.revokeOwner();
  await expect(f.controller.inspect()).rejects.toThrow('OWNER_REVOKED');
});
it('a successful local install never clears an existing unknown native admission or retires a writer by absence', async () => {
  const f = await fixture();
  const key = sha('unknown owned publication');
  await f.store.compareAndSwapConsumerGuardReceipt(
    'plugin',
    f.account,
    key,
    undefined,
    JSON.stringify({ schema: 'publication-managed-job/v1', state: 'UNKNOWN' }),
  );
  await expect(f.controller.install(f.source, 'g1')).rejects.toThrow('DRAIN_UNKNOWN');
  await expect(f.controller.drain(20)).rejects.toThrow('DRAIN_UNKNOWN');
  expect((await f.controller.inspect()).state).toBe('UNKNOWN');
  const original = await f.store.readConsumerGuardReceipt('plugin', f.account, key);
  expect(original?.payload).toBe('{"schema":"publication-managed-job/v1","state":"UNKNOWN"}');
  f.preserved();
});
it('wrong device/corrupt ledger cannot relatch after restoring the old payload', async () => {
  const f = await fixture();
  const r = await f.controller.install(f.source, 'g1');
  await f.controller.switchEntry('g1');
  const row = f.sqlite
    .prepare(
      "SELECT id,payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-managed-lifecycle/v1'",
    )
    .get() as any;
  const changed = JSON.parse(row.payload);
  changed.deviceScopeRef = sha('wrong-device');
  f.sqlite
    .prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?')
    .run(JSON.stringify(changed), row.id);
  await expect(f.controller.verifyCurrent(r.root)).rejects.toThrow('LEDGER');
  f.sqlite.prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?').run(row.payload, row.id);
  await expect(f.controller.verifyCurrent(r.root)).rejects.toThrow('REVOKED');
  f.preserved();
});

/** Test value: original controller API + real SQLite must distinguish actual lifecycle phases,
 * durable counters and opaque authority from JSON. Host source ABI / C lifecycle-source contract.
 * Existing cases covered install/current only, not receipt issuance or delayed transition races.
 * Minimal inputs: one two-file private release, a forged handle/ledger phase, or one paused drain.
 * tier: unit; asynchronous gates avoid sleeps. Real Core/Python load is exercised by the separate
 * cross-repository integration gate; these cases do not replace that gate with a mock receipt.
 */
it('projects completed phases with durable independent counters and invalidates handles synchronously', async () => {
  const f = await fixture();
  const r = await f.controller.install(f.source, 'g1', 'original-install-operation');
  const installed = await f.controller.produceLifecycle('INSTALLED');
  expect(readManagedLifecycleReceipt(installed, f.controller)).toMatchObject({
    schema: 'publication-main-lifecycle-source/v1', scope: 'OWNED_CONTROLLER_ONLY',
    operationId: 'original-install-operation', phase: 'INSTALLED',
    releaseSequence: 1, lifecycleSequence: 1, root: r.root,
    ownedJobs: 0, unresolvedAdmissions: 0, unknownNativeEffects: 0, enrollment: null,
  });
  expect(await f.controller.produceLifecycle('INSTALLED')).toBe(installed);
  const json = JSON.parse(JSON.stringify(readManagedLifecycleReceipt(installed, f.controller)));
  expect(() => readManagedLifecycleReceipt(json, f.controller)).toThrow('LIFECYCLE_RECEIPT');
  const other = new ManagedPublicationController(f.store, 'plugin', f.account, sha('synthetic-device'), f.owner);
  expect(() => readManagedLifecycleReceipt(installed, other)).toThrow('LIFECYCLE_RECEIPT');
  let invalidated = 0;
  const unsubscribe = f.controller.onSourceInvalidated(() => { invalidated++; });
  const switching = f.controller.switchEntry('g1');
  expect(invalidated).toBe(1);
  expect(() => readManagedLifecycleReceipt(installed, f.controller)).toThrow('LIFECYCLE_RECEIPT');
  await switching;
  const switched = await f.controller.produceLifecycle('ENTRY_SWITCHED');
  expect(readManagedLifecycleReceipt(switched, f.controller)).toMatchObject({ releaseSequence: 1, lifecycleSequence: 2 });
  expect(f.controller.currentSourceBinding()).toEqual(readManagedLifecycleReceipt(switched, f.controller).binding);
  await expect(f.controller.produceLifecycle('LOADED', json)).rejects.toThrow('LIFECYCLE_PHASE');
  const revocation = f.controller.revoke();
  expect(invalidated).toBe(2);
  expect(() => f.controller.currentSourceBinding()).toThrow('REVOKED');
  expect(() => readManagedLifecycleReceipt(switched, f.controller)).toThrow('LIFECYCLE_RECEIPT');
  await revocation;
  const revoked = await f.controller.produceLifecycle('REVOKED');
  expect(readManagedLifecycleReceipt(revoked, f.controller)).toMatchObject({ releaseSequence: 1, lifecycleSequence: 3 });
  await f.controller.drain(20);
  const drained = await f.controller.produceLifecycle('DRAINED');
  expect(readManagedLifecycleReceipt(drained, f.controller)).toMatchObject({ releaseSequence: 1, lifecycleSequence: 4 });
  await other.install(f.source, 'g2', 'second-original-operation');
  const next = await other.produceLifecycle('INSTALLED');
  expect(readManagedLifecycleReceipt(next, other)).toMatchObject({
    operationId: 'second-original-operation', releaseSequence: 2, lifecycleSequence: 5,
  });
  unsubscribe();
  f.preserved();
});
it('refuses a forged persisted REVOKED phase and irreversibly closes a drifted source receipt', async () => {
  const f = await fixture();
  await f.controller.install(f.source, 'g1');
  const handle = await f.controller.produceLifecycle('INSTALLED');
  const row = f.sqlite.prepare(
    "SELECT id,payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-managed-lifecycle/v1'",
  ).get() as { id: string; payload: string };
  const forged = { ...JSON.parse(row.payload), state: 'REVOKED', sourcePhase: 'REVOKED' };
  f.sqlite.prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?').run(JSON.stringify(forged), row.id);
  await expect(f.controller.produceLifecycle('REVOKED')).rejects.toThrow('LIFECYCLE_PHASE');
  await expect(f.controller.verifyLifecycleReceipt(handle)).rejects.toThrow('LIFECYCLE_LEDGER_DRIFT');
  f.sqlite.prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?').run(row.payload, row.id);
  expect(() => readManagedLifecycleReceipt(handle, f.controller)).toThrow('LIFECYCLE_RECEIPT');
  await expect(f.controller.verifyLifecycleReceipt(handle)).rejects.toThrow('LIFECYCLE_RECEIPT');
  f.preserved();
});
it('a superseded drain continuation cannot mark a new active generation REVOKED or UNKNOWN', async () => {
  const f = await fixture();
  await f.controller.install(f.source, 'g1');
  await f.controller.switchEntry('g1');
  let resume!: (value: number) => void;
  let reached!: () => void;
  const paused = new Promise<number>((resolve) => { resume = resolve; });
  const entered = new Promise<void>((resolve) => { reached = resolve; });
  const original = f.store.unresolvedConsumerGuardAdmissions;
  let hold = true;
  f.store.unresolvedConsumerGuardAdmissions = async (plugin, account) => {
    if (hold) { hold = false; reached(); return paused; }
    return original(plugin, account);
  };
  const draining = f.controller.drain(30000);
  const expected = expect(draining).rejects.toThrow('REVOKED');
  await entered;
  const successor = await f.controller.install(f.source, 'g2');
  await f.controller.switchEntry('g2');
  const before = await f.controller.inspect();
  resume(0);
  await expected;
  expect(await f.controller.inspect()).toEqual(before);
  f.controller.assertCurrent(successor.root);
  f.preserved();
});
it('reading a restored historical ledger never manufactures source authority in a restarted controller', async () => {
  const f = await fixture();
  await f.controller.install(f.source, 'g1');
  await f.controller.revoke();
  const row = f.sqlite.prepare(
    "SELECT id,payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-managed-lifecycle/v1'",
  ).get() as { id: string; payload: string };
  const legacy = JSON.parse(row.payload);
  for (const key of ['releaseSequence', 'lifecycleSequence', 'operationId', 'sourcePhase']) delete legacy[key];
  f.sqlite.prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?').run(JSON.stringify(legacy), row.id);
  const restarted = new ManagedPublicationController(f.store, 'plugin', f.account, sha('synthetic-device'), f.owner);
  expect((await restarted.inspect()).state).toBe('REVOKED');
  await expect(restarted.produceLifecycle('REVOKED')).rejects.toThrow('LIFECYCLE_PHASE');
  await restarted.install(f.source, 'g2');
  expect(readManagedLifecycleReceipt(await restarted.produceLifecycle('INSTALLED'), restarted)).toMatchObject({
    operationId: 'g2', releaseSequence: 1, lifecycleSequence: 1,
  });
  f.preserved();
});
