/** Actual Store/Drizzle/SQLite predicates; only the competing writes are synthetic. */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/sqlite-proxy';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore, readPublicationHistoryReceipt } from '../restrictedPartnerStore.js';
import { digest } from '../restrictedPublicationProtocol.js';
import { assertNoUncertainPublicationCutover } from '../restrictedPublicationPolicyCutover.js';

const plugin = 'synthetic.owner-drain';
const account = 'a'.repeat(64);
const key = 'b'.repeat(64);
const target = `publication-coverage:${account}:${key}`;
const databases: Database.Database[] = [];
afterEach(() => {
  for (const db of databases.splice(0)) db.close();
});

async function fixture() {
  const db = new Database(':memory:');
  databases.push(db);
  db.exec(
    'CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))',
  );
  let afterNativeRead: (() => void) | undefined;
  let nativeReads = 0;
  // The async proxy executes every real generated SQL statement. A hook may
  // insert a competing write after a SELECT's original rows were obtained;
  // it never substitutes a Store method, SQL result, or native validation.
  const client = {
    drizzle: drizzle(async (sql, params, method) => {
      const statement = db.prepare(sql).raw();
      const result = method === 'run'
        ? { rows: [], ...statement.run(...params) }
        : { rows: method === 'get' ? statement.get(...params) as unknown[] : statement.all(...params) };
      if (sql.startsWith('select ') && sql.includes('native-publication:%')) {
        nativeReads++;
        const hook = afterNativeRead;
        afterNativeRead = undefined;
        hook?.();
      }
      return result;
    }),
  } as unknown as DbClient;
  const store = createRestrictedPartnerStore(client, () => {});
  expect(await store.compareAndSwapConsumerGuardReceipt(
    plugin, account, key, undefined, '{"state":"RETIRING"}',
  )).toBe(true);
  const previous = (await store.readConsumerGuardReceipt(plugin, account, key))!;
  const advance = (requirePublicationDrained = true) => store.compareAndSwapConsumerGuardReceipt(
    plugin, account, key, previous, '{"state":"RETIRED"}', requirePublicationDrained,
  );
  const native = (state = 'APPLIED_VERIFIED', ownPlugin = plugin) => {
    const action = '12345678-1234-1234-1234-123456789abc';
    const payload = {
      schema: 'native-publication-action/v1', pluginId: ownPlugin, nativeActionId: action,
      actionRevision: 1, stateRevision: 1, state, principalId: 'synthetic-principal-中文😀',
      partnerId: 'synthetic-partner', runId: 'synthetic-run', sourceOutputMessageId: 'synthetic-output',
      completedOutputSha256: 'c'.repeat(64), receiptSha256: 'd'.repeat(64),
      effects: state === 'APPLIED_VERIFIED'
        ? ['remote-staging-prepare', 'remote-staging-upload', 'remote-transaction'] : [],
    };
    const nativeTarget = 'restricted:publication:' + digest([
      ownPlugin, payload.principalId, payload.partnerId, payload.runId,
      payload.sourceOutputMessageId, payload.completedOutputSha256, 'PUBLIC_RELEASE',
    ]);
    db.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)').run(
      'native-publication:' + action, ownPlugin, 'target', nativeTarget, nativeTarget,
      digest(payload), JSON.stringify(payload), 1, 1,
    );
  };
  const malformed = () => db.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)').run(
    'native-publication:malformed', plugin, 'target', 'restricted:publication:malformed',
    'malformed', 'bad', '{malformed', 1, 1,
  );
  const admission = () => db.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)').run(
    'late-admission', plugin, 'target', `publication-coverage:${account}:late`, 'late', 'synthetic',
    JSON.stringify({ schema: 'publication-coverage-admission/v1', state: 'UNKNOWN' }), 1, 1,
  );
  return {
    db, store, previous, advance, native, malformed, admission,
    afterNativeRead: (hook: () => void) => { afterNativeRead = hook; },
    nativeReads: () => nativeReads,
  };
}

it.each([false, true])('permits a drained transition with valid applied native history=%s', async applied => {
  const f = await fixture();
  if (applied) f.native();
  expect(await f.advance()).toBe(true);
  expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual({
    revision: f.previous.revision + 1, payload: '{"state":"RETIRED"}',
  });
});

it('refuses an already UNKNOWN native effect and preserves the prior row', async () => {
  const f = await fixture();
  f.native('UNKNOWN');
  expect(await f.advance()).toBe(false);
  expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual(f.previous);
});

it('keeps the original native-record validator for malformed existing history', async () => {
  const f = await fixture();
  f.malformed();
  await expect(f.advance()).rejects.toThrow('PUBLICATION_NATIVE_EFFECT_FACTS_UNKNOWN');
  expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual(f.previous);
});

it('rejects an UNKNOWN admission inserted after the original SELECT', async () => {
  const f = await fixture();
  f.afterNativeRead(f.admission);
  expect(await f.advance()).toBe(false);
  expect(f.nativeReads()).toBe(1);
  expect(await f.store.unresolvedConsumerGuardAdmissions(plugin, account)).toBe(1);
  expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual(f.previous);
});

it.each(['malformed-insert', 'forged-applied-insert', 'payload-change', 'fingerprint-change', 'delete'])(
  'rejects native history drift after validation: %s', async mutation => {
    const f = await fixture();
    if (['payload-change', 'fingerprint-change', 'delete'].includes(mutation)) f.native();
    f.afterNativeRead(() => {
      if (mutation === 'malformed-insert') f.malformed();
      else if (mutation === 'forged-applied-insert') {
        f.native();
        f.db.prepare("UPDATE plugin_task_requests SET fingerprint='forged' WHERE id LIKE 'native-publication:%'").run();
      } else if (mutation === 'payload-change') {
        f.db.prepare("UPDATE plugin_task_requests SET payload='{malformed' WHERE id LIKE 'native-publication:%'").run();
      } else if (mutation === 'fingerprint-change') {
        f.db.prepare("UPDATE plugin_task_requests SET fingerprint='changed' WHERE id LIKE 'native-publication:%'").run();
      } else {
        f.db.prepare("DELETE FROM plugin_task_requests WHERE id LIKE 'native-publication:%'").run();
      }
    });
    expect(await f.advance()).toBe(false);
    expect(f.nativeReads()).toBe(1);
    expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual(f.previous);
  },
);

it('preserves a competing winner of the original receipt CAS', async () => {
  const f = await fixture();
  f.afterNativeRead(() => {
    f.db.prepare('UPDATE plugin_task_requests SET payload=?,revision=? WHERE target_id=? AND plugin_id=?')
      .run('{"state":"FOREIGN_WINNER"}', f.previous.revision + 1, target, plugin);
  });
  expect(await f.advance()).toBe(false);
  expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual({
    revision: f.previous.revision + 1, payload: '{"state":"FOREIGN_WINNER"}',
  });
});

/** Source-closure regression: a census cannot omit terminal/old rows or race
 * a new original registration between a complete read and its committing CAS.
 * These exercise the production Store and actual SQLite; no source facts are
 * fabricated. The existing drain tests do not cover full owner-row snapshots.
 * Minimal input: one old terminal row and a concurrent original-table insert.
 * Tier: existing SQLite Store integration fixture in this file.
 */
it('captures the complete original owner history, including old terminal rows', async () => {
  const f = await fixture();
  const oldKey = 'c'.repeat(64);
  await f.store.compareAndSwapConsumerGuardReceipt(plugin, account, oldKey, undefined,
    JSON.stringify({ schema: 'publication-original-owner-listener/v1', state: 'REVOKED', generation: 'old' }));
  f.db.prepare('UPDATE plugin_task_requests SET created_at=1 WHERE request_key=?').run(oldKey);
  const handle = await f.store.capturePublicationOwnerHistory(plugin, account);
  const actual = readPublicationHistoryReceipt(handle, f.store.consumerGuardReceiptIdentity, plugin, account);
  expect(actual.rows.map(x => x.requestKey).sort()).toEqual([key, oldKey].sort());
  expect(actual.rows.find(x => x.requestKey === oldKey)?.createdAt).toBe(1);
  await expect(f.store.assertPublicationOwnerHistoryCurrent(handle, plugin, account)).resolves.toBeUndefined();
  expect(() => readPublicationHistoryReceipt(structuredClone(handle), f.store.consumerGuardReceiptIdentity, plugin, account))
    .toThrow('PUBLICATION_OWNER_HISTORY_HANDLE_REQUIRED');
  expect(() => readPublicationHistoryReceipt(handle, f.store.consumerGuardReceiptIdentity, plugin, 'd'.repeat(64)))
    .toThrow('PUBLICATION_OWNER_HISTORY_HANDLE_REQUIRED');
});

it.each(['insert', 'delete', 'change'])(
  'binds the complete owner history to the final drain CAS against %s', async mutation => {
    const f = await fixture();
    const oldKey = 'c'.repeat(64);
    await f.store.compareAndSwapConsumerGuardReceipt(plugin, account, oldKey, undefined,
      JSON.stringify({ state: 'OLD_RETIRED' }));
    const handle = await f.store.capturePublicationOwnerHistory(plugin, account);
    f.afterNativeRead(() => {
      if (mutation === 'insert') {
        const lateKey = 'd'.repeat(64);
        f.db.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)').run(
          `publication-coverage:${plugin}:${account}:${lateKey}`, plugin, 'target',
          `publication-coverage:${account}:${lateKey}`, lateKey, account,
          '{"state":"STARTING"}', 1, 1,
        );
      } else if (mutation === 'delete') {
        f.db.prepare('DELETE FROM plugin_task_requests WHERE request_key=?').run(oldKey);
      } else {
        f.db.prepare('UPDATE plugin_task_requests SET payload=?,revision=revision+1 WHERE request_key=?')
          .run('{"state":"UNKNOWN"}', oldKey);
      }
    });
    expect(await f.store.compareAndSwapConsumerGuardReceipt(plugin, account, key, f.previous,
      '{"state":"RETIRED"}', true, handle)).toBe(false);
    expect(await f.store.readConsumerGuardReceipt(plugin, account, key)).toEqual(f.previous);
    await expect(f.store.assertPublicationOwnerHistoryCurrent(handle, plugin, account))
      .rejects.toThrow('PUBLICATION_OWNER_HISTORY_CHANGED');
  },
);

it('rejects malformed original history rather than removing it from the census', async () => {
  const f = await fixture();
  f.db.prepare('UPDATE plugin_task_requests SET operation=?,payload=? WHERE request_key=?')
    .run('foreign-operation', '{malformed', key);
  await expect(f.store.capturePublicationOwnerHistory(plugin, account))
    .rejects.toThrow('PUBLICATION_OWNER_HISTORY_UNKNOWN');
});

it('keeps native history scoped to the original plugin', async () => {
  const f = await fixture();
  f.afterNativeRead(() => f.native('UNKNOWN', 'synthetic.other-plugin'));
  expect(await f.advance()).toBe(true);
});

it('requires an existing receipt when requesting the atomic drain gate', async () => {
  const f = await fixture();
  await expect(f.store.compareAndSwapConsumerGuardReceipt(
    plugin, account, 'e'.repeat(64), undefined, '{}', true,
  )).rejects.toThrow('PUBLICATION_COVERAGE_RECEIPT_INVALID');
  expect(await f.store.readConsumerGuardReceipt(plugin, account, 'e'.repeat(64))).toBeUndefined();
});

it('a cutover preflight cannot adopt a competing row after its real history capture', async () => {
  const f = await fixture();
  const racingStore = { ...f.store, capturePublicationOwnerHistory: async (p: string, a: string) => {
    const actual = await f.store.capturePublicationOwnerHistory(p, a);
    // Inject a competing SQLite write after the real private snapshot. The
    // original handle and Store verification are never replaced by JSON.
    f.db.prepare('UPDATE plugin_task_requests SET payload=?,revision=revision+1 WHERE request_key=?')
      .run('{"state":"UNKNOWN"}', key);
    return actual;
  } };
  await expect(assertNoUncertainPublicationCutover(racingStore, plugin, account))
    .rejects.toThrow('PUBLICATION_OWNER_HISTORY_CHANGED');
  expect((await f.store.readConsumerGuardReceipt(plugin, account, key))?.payload).toBe('{"state":"UNKNOWN"}');
});

it('preserves existing CAS behavior when no drain gate is requested', async () => {
  const f = await fixture();
  f.admission();
  expect(await f.advance(false)).toBe(true);
  expect(await f.store.unresolvedConsumerGuardAdmissions(plugin, account)).toBe(1);
});
