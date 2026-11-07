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
