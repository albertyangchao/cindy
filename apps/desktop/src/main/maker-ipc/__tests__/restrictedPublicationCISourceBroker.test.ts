/** Test value (unit, following the existing account-SQLite fixtures):
 * Main source startup must persist an original operation before opening a process,
 * refuse stale owners/oversize input, and keep UNKNOWN non-retryable. Host94 had no
 * source broker. These smallest preflight inputs execute no external program.
 * Real B/C/Python/gh-boundary integration is a separate exact-source gate, not
 * replaced by these preflight tests or a mock Python receipt factory.
 */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { digest } from '../restrictedPublicationProtocol.js';
import {
  RestrictedPublicationCISourceBroker,
  readPublicationSourceReceipt,
  type PinnedPublicationSourceWorker,
  type PublicationSourceBinding,
} from '../restrictedPublicationCISourceBroker.js';

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => { for (const release of cleanup.splice(0).reverse()) await release(); });
async function fixture() {
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'main-source-preflight-')));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = new Database(':memory:');
  cleanup.push(async () => db.close());
  db.exec('CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))');
  let live = true;
  const owner = () => { if (!live) throw Error('OWNER_CHANGED'); };
  const store = createRestrictedPartnerStore({ drizzle: drizzle(db) } as unknown as DbClient, owner);
  const expected: PublicationSourceBinding = {
    accountId: digest('account'), deviceId: digest('device'), bootId: 'test-boot', ownerEpoch: 1, generation: 'test-g1',
  };
  const profile: PinnedPublicationSourceWorker = {
    root: dir, files: {},
    python: { path: path.join(dir, 'not-executed'), sha256: 'a'.repeat(64) },
    gh: { path: path.join(dir, 'not-executed'), sha256: 'b'.repeat(64), homeDirectory: dir, configDirectory: dir },
  };
  const current = () => { owner(); return { ...expected }; };
  const start = (op: string, value = expected) => RestrictedPublicationCISourceBroker.startOwned(
    store, 'plugin', op, profile, value, current,
  );
  return { dir, db, store, expected, profile, start, revoke: () => { live = false; } };
}

it('failed source startup consumes the exact operation without changing old UNKNOWN records', async () => {
  const f = await fixture();
  f.db.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)').run(
    'old-input', 'plugin', 'target', 'restricted:input:old', 'old', 'old', '{"state":"UNKNOWN"}', 1, 1,
  );
  await expect(f.start('source-op')).rejects.toThrow('SOURCE_PROFILE');
  const key = digest(['publication-main-source-operation/v1', 'source-op']);
  const before = await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key);
  expect(JSON.parse(before!.payload).state).toBe('UNKNOWN');
  await expect(f.start('source-op')).rejects.toThrow('OPERATION_ALREADY_CLAIMED');
  expect(await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key)).toEqual(before);
  expect(f.db.prepare('SELECT payload,revision FROM plugin_task_requests WHERE id=?').get('old-input'))
    .toEqual({ payload: '{"state":"UNKNOWN"}', revision: 1 });
});

it('changed owner refuses before claiming a source operation or opening its paths', async () => {
  const f = await fixture();
  f.revoke();
  await expect(f.start('unclaimed')).rejects.toThrow('OWNER_CHANGED');
  expect(f.db.prepare('SELECT count(*) AS n FROM plugin_task_requests').get()).toEqual({ n: 0 });
});

it('account binding mismatch cannot borrow the current Main owner', async () => {
  const f = await fixture();
  await expect(f.start('foreign-owner', { ...f.expected, accountId: digest('other-account') }))
    .rejects.toThrow('OWNER_CHANGED');
  expect(f.db.prepare('SELECT count(*) AS n FROM plugin_task_requests').get()).toEqual({ n: 0 });
});

it('source byte bound rejects a regular oversize file before any executable starts', async () => {
  const f = await fixture();
  const files: Record<string, string> = {};
  for (const relative of ['scripts/publication_coverage_source_worker.py', 'bridge_core/__init__.py', 'bridge_core/worksheet_ci_guard_receipt.py']) {
    const target = path.join(f.dir, relative);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    const data = '# preflight fixture; never executed\n';
    await writeFile(target, data, { mode: 0o600 });
    files[relative] = createHash('sha256').update(data).digest('hex');
  }
  f.profile.files = files;
  await truncate(path.join(f.dir, 'scripts/publication_coverage_source_worker.py'), 4 * 1048576 + 1);
  await expect(f.start('oversize')).rejects.toThrow('PIN_LIMIT');
  const row = await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId,
    digest(['publication-main-source-operation/v1', 'oversize']));
  expect(JSON.parse(row!.payload).state).toBe('UNKNOWN');
  expect(() => readPublicationSourceReceipt(JSON.parse('{}'), Object.create(null)))
    .toThrow('PRIVATE_RECEIPT_REQUIRED');
});
