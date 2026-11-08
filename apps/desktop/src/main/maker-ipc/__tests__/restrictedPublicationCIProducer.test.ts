/** Test value: CI effects must participate in the original SQLite drain/CAS
 * gate, and raw observations must not mint Main capabilities. These are actual
 * database and protocol-denial tests, not a simulated authenticated CI owner.
 * Regression: one UNKNOWN runner row previously escaped the drain predicate.
 * Tier: unit (in-memory SQLite, no network, runner, install or process start).
 */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { canonical, digest } from '../restrictedPublicationProtocol.js';
import { RestrictedPublicationResidentSource } from '../restrictedPublicationResidentSource.js';
import { RestrictedPublicationCIProducer, consumeOriginalCIEffectPermit, originalCIEffectIdentity,
  originalCIEffectTarget, originalCIEffectPlanIdentity, matchesOriginalCIEffectPlan,
  validateOriginalCIEffect, type OriginalCIEffectDescriptor } from '../restrictedPublicationCIProducer.js';

const databases: Database.Database[] = [];
afterEach(() => { for (const db of databases.splice(0)) db.close(); });
function fixture() {
  const db = new Database(':memory:'); databases.push(db);
  db.exec('CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))');
  const store = createRestrictedPartnerStore({ drizzle: drizzle(db) } as unknown as DbClient, () => {});
  return { db, store, account: digest('ci-account'), plugin: 'ci-test-plugin' };
}
const descriptor: OriginalCIEffectDescriptor = { schema: 'publication-ci-effect/v1', kind: 'controller-start',
  identity: { repository: 'albertyangchao/core-bridge', runId: 41, attempt: 1,
    route: 'valerie-bridge', controllerSha256: digest('controller') } };

it.each(['DISPATCHING_UNKNOWN', 'APPLIED_UNACKNOWLEDGED', 'UNKNOWN'])(
  'the original drain CAS observes a real CI %s row and preserves the pending drain', async state => {
    const f = fixture(), key = digest(['publication-ci-runner-effect/v1', originalCIEffectTarget(descriptor)]);
    await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, key, undefined,
      canonical({ schema: 'publication-ci-runner-effect/v1', state, operationId: 'original' }));
    expect(await f.store.unresolvedConsumerGuardAdmissions(f.plugin, f.account)).toBe(1);
    const drainKey = digest('original-drain');
    await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, drainKey, undefined,
      canonical({ schema: 'drain-test-record/v1', state: 'PENDING' }));
    const before = (await f.store.readConsumerGuardReceipt(f.plugin, f.account, drainKey))!;
    const history = await f.store.capturePublicationOwnerHistory(f.plugin, f.account);
    expect(await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, drainKey, before,
      canonical({ schema: 'drain-test-record/v1', state: 'DRAINED' }), true, history)).toBe(false);
    expect(await f.store.readConsumerGuardReceipt(f.plugin, f.account, drainKey)).toEqual(before);
  });

it('a durable COMPLETE effect is resolved but cannot be resubmitted under a new operation', async () => {
  const f = fixture(), key = digest(['publication-ci-runner-effect/v1', originalCIEffectTarget(descriptor)]);
  await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, key, undefined,
    canonical({ schema: 'publication-ci-runner-effect/v1', state: 'COMPLETE', operationId: 'first' }));
  const before = await f.store.readConsumerGuardReceipt(f.plugin, f.account, key);
  expect(await f.store.unresolvedConsumerGuardAdmissions(f.plugin, f.account)).toBe(0);
  expect(await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, key, undefined,
    canonical({ schema: 'publication-ci-runner-effect/v1', state: 'DISPATCHING_UNKNOWN', operationId: 'replacement' }))).toBe(false);
  expect(await f.store.readConsumerGuardReceipt(f.plugin, f.account, key)).toEqual(before);
});

it('a stale outcome writer cannot overwrite a concurrent UNKNOWN winner', async () => {
  const f = fixture(), key = digest('stable-effect');
  await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, key, undefined,
    canonical({ schema: 'publication-ci-runner-effect/v1', state: 'DISPATCHING_UNKNOWN' }));
  const before = (await f.store.readConsumerGuardReceipt(f.plugin, f.account, key))!;
  await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, key, before,
    canonical({ schema: 'publication-ci-runner-effect/v1', state: 'UNKNOWN' }));
  const winner = await f.store.readConsumerGuardReceipt(f.plugin, f.account, key);
  expect(await f.store.compareAndSwapConsumerGuardReceipt(f.plugin, f.account, key, before,
    canonical({ schema: 'publication-ci-runner-effect/v1', state: 'COMPLETE' }))).toBe(false);
  expect(await f.store.readConsumerGuardReceipt(f.plugin, f.account, key)).toEqual(winner);
});

it('caller JSON and class prototypes cannot create a runner owner or effect permit', async () => {
  const f = fixture();
  const source = Object.create(RestrictedPublicationResidentSource.prototype) as RestrictedPublicationResidentSource;
  expect(() => RestrictedPublicationCIProducer.fromOriginal(f.store, f.plugin, source, {},
    { instanceId: 'original', effects: [descriptor], assertEffectApproved: () => {} })).toThrow('ORIGINAL_SOURCE_REQUIRED');
  for (const handle of [{}, { state: 'DISPATCHING_UNKNOWN', admissionId: digest('forged') }]) {
    await expect(consumeOriginalCIEffectPermit(handle, source, {} as never, 'admit')).rejects.toThrow('PRIVATE_PERMIT_REQUIRED');
    await expect(consumeOriginalCIEffectPermit(handle, source, {} as never, 'ack')).rejects.toThrow('PRIVATE_PERMIT_REQUIRED');
  }
});

it('binds effect outcomes to their exact descriptor and admission without allowing a pending success', () => {
  const effectId = originalCIEffectIdentity(descriptor), admissionId = digest('admission');
  const requested = { sequence: 1, effectId, descriptorSha256: effectId, descriptor,
    state: 'REQUESTED', admissionId: null, outcome: null, outcomeSha256: null };
  expect(() => validateOriginalCIEffect(requested)).not.toThrow();
  expect(() => validateOriginalCIEffect({ ...requested, sequence: 0 })).toThrow('EFFECT');
  expect(() => validateOriginalCIEffect({ ...requested, sequence: 128 })).not.toThrow();
  expect(() => validateOriginalCIEffect({ ...requested, sequence: 129 })).toThrow('EFFECT');
  expect(() => validateOriginalCIEffect({ ...requested, admissionId })).toThrow('EFFECT');
  const outcome = { schema: 'publication-ci-effect-outcome/v1', effectId, descriptorSha256: effectId,
    admissionId, state: 'SUCCEEDED', result: { processId: 42 } };
  const succeeded = { ...requested, state: 'SUCCEEDED', admissionId, outcome, outcomeSha256: digest(outcome) };
  expect(() => validateOriginalCIEffect(succeeded)).not.toThrow();
  expect(() => validateOriginalCIEffect({ ...succeeded, admissionId: digest('different') })).toThrow('OUTCOME');
  expect(() => validateOriginalCIEffect({ ...succeeded, descriptor: { ...descriptor, identity: { runId: 42 } } })).toThrow('EFFECT');
});

it('keeps descriptor byte limits and explicit effect kinds', () => {
  expect(() => originalCIEffectIdentity({ ...descriptor, identity: { target: 'x'.repeat(8193) } })).toThrow('DESCRIPTOR');
  expect(() => originalCIEffectIdentity({ ...descriptor, kind: 'arbitrary-shell' })).toThrow('DESCRIPTOR');
});

it('a source/config hash change cannot make the same runner target retryable', () => {
  const changed = { ...descriptor, identity: { ...descriptor.identity, controllerSha256: digest('new-source') } };
  expect(originalCIEffectIdentity(changed)).not.toBe(originalCIEffectIdentity(descriptor));
  expect(originalCIEffectTarget(changed)).toBe(originalCIEffectTarget(descriptor));
  const pool: OriginalCIEffectDescriptor = { schema: 'publication-ci-effect/v1', kind: 'persistent-configure',
    identity: { repository: 'albertyangchao/core-bridge', poolId: 'valerie-bridge-ci', distro: 'ValerieCI',
      runnerNames: ['windows-ayc-core-bridge-ci-02', 'windows-ayc-core-bridge-ci-01'], poolDigest: digest('old') } };
  expect(originalCIEffectTarget({ ...pool, identity: { ...pool.identity, poolDigest: digest('new'),
    runnerNames: [...pool.identity.runnerNames as string[]].reverse() } })).toBe(originalCIEffectTarget(pool));
  expect(originalCIEffectTarget({ ...descriptor, identity: { ...descriptor.identity, runId: 42 } }))
    .not.toBe(originalCIEffectTarget(descriptor));
});

it('binds the one late retirement observation without changing any fixed Main target', () => {
  // Expectation/descriptor comparison only: no private peer or permit is made.
  const expected: OriginalCIEffectDescriptor = { schema: 'publication-ci-effect/v1', kind: 'persistent-retire',
    identity: { repository: 'albertyangchao/core-bridge', poolId: 'valerie-bridge-ci', poolDigest: digest('pool'),
      runnerName: 'windows-ayc-core-bridge-ci-03', runnerId: 83, distro: 'ValerieCI',
      unit: 'actions.runner.albertyangchao-core-bridge.windows-ayc-core-bridge-ci-03.service' } };
  const observed = { ...expected, identity: { ...expected.identity, unitInvocationId: 'a'.repeat(32) } };
  expect(matchesOriginalCIEffectPlan(expected, observed)).toBe(true);
  expect(originalCIEffectIdentity(observed)).not.toBe(originalCIEffectPlanIdentity(expected));
  expect(originalCIEffectTarget(observed)).toBe(originalCIEffectTarget(expected));
  for (const change of [{ runnerId: 84 }, { poolDigest: digest('different') }, { unit: 'another.service' }])
    expect(matchesOriginalCIEffectPlan(expected, { ...observed, identity: { ...observed.identity, ...change } })).toBe(false);
  expect(matchesOriginalCIEffectPlan(observed, { ...observed,
    identity: { ...observed.identity, unitInvocationId: 'b'.repeat(32) } })).toBe(false);
  expect(() => matchesOriginalCIEffectPlan(expected, { ...observed,
    identity: { ...observed.identity, unitInvocationId: '' } })).toThrow('EFFECT');
  for (const value of [null, undefined, ''])
    expect(() => originalCIEffectPlanIdentity({ ...expected,
      identity: { ...expected.identity, unitInvocationId: value } })).toThrow('PLAN');
  const missing = { ...expected.identity }; delete missing.poolDigest;
  expect(() => originalCIEffectPlanIdentity({ ...expected, identity: missing })).toThrow('SCHEMA');
  expect(() => originalCIEffectPlanIdentity({ ...expected,
    identity: { ...expected.identity, extraObservedFact: 'not-allowed' } })).toThrow('SCHEMA');
  expect(() => originalCIEffectPlanIdentity({ schema: 'publication-ci-effect/v1', kind: 'controller-start',
    identity: { repository: 'albertyangchao/core-bridge', route: 'valerie-bridge', runId: 41 } })).toThrow('SCHEMA');
});
