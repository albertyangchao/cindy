/** Real SQLite/filesystem/Controller negative and lifecycle integration only.
 * No original resident, EOF, census or policy success is simulated. */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { digest } from '../restrictedPublicationProtocol.js';
import { ManagedPublicationController, type PublisherReleaseSource } from '../restrictedPublicationManagedController.js';
import { RestrictedPublicationOwnerRegistry, verifyOriginalRetirementReceipt } from '../restrictedPublicationOwnerRegistry.js';
import { RestrictedPublicationResidentSource } from '../restrictedPublicationResidentSource.js';
import { assertNoUncertainPublicationCutover, commitPublicationGenerationCutover,
  preparePublicationGenerationCutover, clonePublicationGenerationPlan, publicationGenerationPlanIdentity,
  type MainPublicationGenerationPlan } from '../restrictedPublicationPolicyCutover.js';

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close(); });
const rawHash = (raw: string) => createHash('sha256').update(raw).digest('hex');

// Metadata-only regression: structuredClone must retain private Main callbacks
// outside its serialized value while deeply copying every approved CI target.
// This does not produce an installation, original source or approval receipt.
it('clones CI runner expectations without serializing or executing their Main approval', () => {
  let approvals = 0;
  const approve = () => { approvals++; };
  const plan = { generation: 'next', profile: {}, sourcePlan: { operationId: 'next-op', worker: {},
    ciRunners: [{ instanceId: 'original-controller', effects: [{ schema: 'publication-ci-effect/v1',
      kind: 'controller-start', identity: { runId: 42 } }], assertEffectApproved: approve }] } } as unknown as MainPublicationGenerationPlan;
  const identity = publicationGenerationPlanIdentity(plan);
  const copy = clonePublicationGenerationPlan(plan);
  expect(copy.sourcePlan.ciRunners![0].assertEffectApproved).toBe(approve);
  expect(approvals).toBe(0);
  expect(publicationGenerationPlanIdentity(copy)).toBe(identity);
  plan.sourcePlan.ciRunners![0].effects[0].identity.runId = 43;
  expect(copy.sourcePlan.ciRunners![0].effects[0].identity.runId).toBe(42);
  expect(publicationGenerationPlanIdentity(plan)).not.toBe(identity);
});
async function fixture() {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'main-policy-cutover-')));
  cleanup.push(() => rm(directory, { recursive: true, force: true }));
  const db = new Database(':memory:'); cleanup.push(async () => db.close());
  db.exec('CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))');
  const store = createRestrictedPartnerStore({ drizzle: drizzle(db) } as unknown as DbClient, () => {});
  const account = digest('cutover-test-account'), device = digest('cutover-test-device');
  const controller = new ManagedPublicationController(store, 'plugin', account, device, () => {});
  const root = path.join(directory, 'source'), releases = path.join(directory, 'releases');
  await mkdir(root, { mode: 0o700 }); await mkdir(releases, { mode: 0o700 });
  const files: Record<string, string> = {};
  for (const name of ['bridge_core/publication_consumer_controller.py', 'scripts/publish_generic_html_direct.py']) {
    const data = '# explicitly synthetic fixture; never executed\n';
    await mkdir(path.dirname(path.join(root, name)), { recursive: true, mode: 0o700 });
    await writeFile(path.join(root, name), data, { mode: 0o600 }); files[name] = rawHash(data);
  }
  const python = path.join(directory, 'non-executable-interpreter');
  await writeFile(python, 'never executed', { mode: 0o600 });
  const source: PublisherReleaseSource = { sourceRoot: root, releasesRoot: releases, files,
    python: { path: python, sha256: rawHash('never executed') } };
  await controller.install(source, 'old-generation', 'old-operation');
  await controller.switchEntry('old-generation');
  await controller.revoke(); await controller.drain(20);
  const drained = await controller.produceLifecycle('DRAINED');
  return { directory, db, store, account, controller, source, drained };
}

it('a real staged managed release blocks replay through the original account history until its original commit', async () => {
  const f = await fixture();
  await assertNoUncertainPublicationCutover(f.store, 'plugin', f.account);
  const prepared = await f.controller.prepareInstall(f.source, 'next-generation', 'next-operation', f.drained);
  await expect(assertNoUncertainPublicationCutover(f.store, 'plugin', f.account)).rejects.toThrow('PRIOR_CUTOVER_UNKNOWN');
  const before = f.db.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all();
  await expect(commitPublicationGenerationCutover(JSON.parse('{}'), {}, f.controller, 'next-generation'))
    .rejects.toThrow('PRIVATE_PREPARATION_REQUIRED');
  expect(f.db.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all()).toEqual(before);
  await f.controller.commitPreparedInstall(prepared);
  await assertNoUncertainPublicationCutover(f.store, 'plugin', f.account);
  // Committing an owned tree does not produce a policy capability or original
  // source fact. A serialized prepared/committed receipt still cannot be used.
  await expect(commitPublicationGenerationCutover({ state: 'COMMITTED' }, {}, f.controller, 'next-generation'))
    .rejects.toThrow('PRIVATE_PREPARATION_REQUIRED');
});

it('an actual managed copy failure remains a history blocker on a fresh operation', async () => {
  const f = await fixture();
  await writeFile(path.join(f.source.sourceRoot, 'scripts/publish_generic_html_direct.py'), '# changed exact source\n', { mode: 0o600 });
  await expect(f.controller.prepareInstall(f.source, 'next-generation', 'next-operation', f.drained)).rejects.toThrow();
  await expect(assertNoUncertainPublicationCutover(f.store, 'plugin', f.account)).rejects.toThrow('PRIOR_CUTOVER_UNKNOWN');
  await expect(f.controller.prepareInstall(f.source, 'next-generation', 'fresh-operation', f.drained)).rejects.toThrow('GENERATION_PREPARED');
});

it('JSON and prototype owners cannot turn a real DRAINED handle into a source-policy cutover', async () => {
  const f = await fixture();
  const registry = Object.create(RestrictedPublicationOwnerRegistry.prototype) as RestrictedPublicationOwnerRegistry;
  const source = Object.create(RestrictedPublicationResidentSource.prototype) as RestrictedPublicationResidentSource;
  const before = f.db.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all();
  await expect(preparePublicationGenerationCutover({}, f.store, 'plugin', f.controller, registry, {}, f.drained,
    [{ source, handle: {} }], {} as MainPublicationGenerationPlan, () => {})).rejects.toThrow('OWNER');
  await expect(verifyOriginalRetirementReceipt({}, registry, source, f.controller, f.drained))
    .rejects.toThrow('PRIVATE_RETIREMENT_REQUIRED');
  await expect(registry.validateCutoverDefinition({}, f.drained, {} as never))
    .rejects.toThrow('PRIVATE_RETIREMENT_REQUIRED');
  expect(f.db.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all()).toEqual(before);
});

it.each(['UNKNOWN', 'ROTATING_UNKNOWN', 'CUTOVER_HELD'])('a persisted listener %s cannot be retried via another generation', async state => {
  const f = await fixture();
  const key = digest(['prior-listener-negative', state]);
  expect(await f.store.compareAndSwapConsumerGuardReceipt('plugin', f.account, key, undefined,
    JSON.stringify({ schema: 'publication-original-owner-listener/v1', state }))).toBe(true);
  const before = f.db.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all();
  await expect(assertNoUncertainPublicationCutover(f.store, 'plugin', f.account)).rejects.toThrow('PRIOR_CUTOVER_UNKNOWN');
  expect(f.db.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all()).toEqual(before);
});
