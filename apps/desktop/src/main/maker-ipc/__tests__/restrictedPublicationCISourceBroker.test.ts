/** Test value (unit, following the existing account-SQLite fixtures):
 * Main source startup must persist an original operation before opening a process,
 * refuse stale owners/oversize input, and keep UNKNOWN non-retryable. Host94 had no
 * source broker. These smallest preflight inputs execute no external program.
 * Real B/C/Python/gh-boundary integration is a separate exact-source gate, not
 * replaced by these preflight tests or a mock Python receipt factory.
 */
import { afterEach, expect, it, vi } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
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
afterEach(async () => {
  vi.restoreAllMocks();
  for (const release of cleanup.splice(0).reverse()) await release();
});
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
  return { dir, db, store, expected, profile, start, current, revoke: () => { live = false; } };
}

/** Pinned inert metadata only. None of these fixture bytes is executed or
 * accepted as an original C/B source receipt. */
async function preparedFixture() {
  const f = await fixture();
  const put = async (relative: string, data: string) => {
    const target = path.join(f.dir, relative);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, data, { mode: 0o600 });
    return createHash('sha256').update(data).digest('hex');
  };
  const files: Record<string, string> = {};
  for (const name of ['scripts/publication_coverage_source_worker.py', 'scripts/__init__.py',
    'bridge_core/__init__.py', 'bridge_core/worksheet_ci_guard_receipt.py'])
    files[name] = await put(name, '# inert preparation fixture\n');
  f.profile.files = files;
  const executable = await put('not-executed', 'inert metadata executable\n');
  f.profile.python.sha256 = executable; f.profile.gh.sha256 = executable;
  const monitorSha256 = await put('monitor/publication_definition_receipts.py', '# inert C expectation\n');
  const definition = { sourceRoot: f.dir, monitorRoot: f.dir, sourceFiles: files };
  const profileSha256 = await put('definition.json', JSON.stringify(definition));
  f.profile.definition = { monitorRoot: f.dir, monitorSha256,
    profilePath: path.join(f.dir, 'definition.json'), profileSha256 };
  const broker = await RestrictedPublicationCISourceBroker.prepareOwned(f.store, 'plugin', 'prepared-operation',
    f.profile, f.expected, f.current);
  cleanup.push(() => broker.revoke());
  return { ...f, broker, definition };
}

it('prepares only pinned expectations without aging a lease or claiming a worker operation', async () => {
  const f = await preparedFixture();
  const now = performance.now();
  vi.spyOn(performance, 'now').mockReturnValue(now + 600000);
  expect(f.broker.preparedDefinitionExpectations()).toEqual(f.definition);
  expect(() => f.broker.assertCurrent()).toThrow('ACTIVE_PHASE_REQUIRED');
  expect(() => f.broker.definitionExpectations()).toThrow('ACTIVE_PHASE_REQUIRED');
  await expect(f.broker.dispatchOriginalCI('a'.repeat(40), 'b'.repeat(64), () => {
    throw Error('must not reach approval');
  })).rejects.toThrow('ACTIVE_PHASE_REQUIRED');
  expect(f.db.prepare('SELECT count(*) AS n FROM plugin_task_requests').get()).toEqual({ n: 0 });
  expect(f.broker.diagnostics()).toMatchObject({ phase: 'PREPARED', state: 'OPENING', runId: null });
});

it('revalidates prepared bytes at activation and permanently consumes a changed-source operation', async () => {
  const f = await preparedFixture();
  await writeFile(path.join(f.dir, 'bridge_core/worksheet_ci_guard_receipt.py'), '# changed before activation\n');
  await expect(f.broker.activatePrepared()).rejects.toThrow('SOURCE_CHANGED');
  const key = digest(['publication-main-source-operation/v1', 'prepared-operation']);
  const row = await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key);
  expect(JSON.parse(row!.payload).state).toBe('UNKNOWN');
  await expect(f.broker.activatePrepared()).rejects.toThrow('CLOSED');
  expect(await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key)).toEqual(row);
});

it('revokes unused prepared expectations without manufacturing an operation record', async () => {
  const f = await preparedFixture();
  await f.broker.revoke();
  expect(() => f.broker.preparedDefinitionExpectations()).toThrow('CLOSED');
  expect(f.db.prepare('SELECT count(*) AS n FROM plugin_task_requests').get()).toEqual({ n: 0 });
});

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
