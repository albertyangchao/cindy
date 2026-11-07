/** Unit negatives use actual account SQLite/install lifecycle; no fake receipt can become READY.
 * Real Python/Core positive integration is the explicit source-bound cross-repository gate. */
import { afterEach, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import {
  ManagedPublicationController,
  readManagedEnrollmentReceipt,
} from '../restrictedPublicationManagedController.js';
import {
  ManagedCoverageDriver,
  type FixedCoverageProfile,
} from '../restrictedPublicationCoverageDriver.js';
import { coverageEntries } from '../restrictedPublicationConsumerGuardAuthority.js';
import { resolveControlledPublicationRoot } from '../restrictedPublicationCaller.js';
const sha = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
const clean: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const f of clean.splice(0)) await f();
});
async function fixture() {
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'coverage-driver-')));
  clean.push(() => rm(dir, { recursive: true, force: true }));
  const db = new Database(':memory:');
  clean.push(async () => db.close());
  db.exec(
    'CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))',
  );
  let live = true;
  const current = () => {
    if (!live) throw Error('OWNER_REVOKED');
  };
  const store = createRestrictedPartnerStore(
    { drizzle: drizzle(db) } as unknown as DbClient,
    current,
  );
  const account = sha('synthetic-account'),
    device = sha('synthetic-device');
  const sourceRoot = path.join(dir, 'source'),
    releasesRoot = path.join(dir, 'releases'),
    bin = path.join(dir, 'bin');
  for (const p of [sourceRoot, releasesRoot, bin]) await mkdir(p, { mode: 0o700 });
  const files: Record<string, string> = {};
  for (const p of [
    'bridge_core/publication_consumer_controller.py',
    'scripts/publish_generic_html_direct.py',
  ]) {
    await mkdir(path.dirname(path.join(sourceRoot, p)), { recursive: true, mode: 0o700 });
    const data = '# synthetic source, never executed';
    await writeFile(path.join(sourceRoot, p), data, { mode: 0o600 });
    files[p] = createHash('sha256').update(data).digest('hex');
  }
  const python = path.join(bin, 'not-executed');
  await writeFile(python, 'synthetic interpreter not executed', { mode: 0o600 });
  const instances = coverageEntries.map((entryId) => ({
    instanceId: 'instance:' + entryId,
    entryId,
    entryDefinitionDigest: sha(entryId),
  }));
  const profile: FixedCoverageProfile = {
    source: {
      sourceRoot,
      releasesRoot,
      python: {
        path: python,
        sha256: createHash('sha256').update('synthetic interpreter not executed').digest('hex'),
      },
      files,
    },
    publisher: {
      artifactRoot: dir,
      queueRoot: dir,
      dispatchRoot: dir,
      publicOrigin: 'https://reports.example.test',
    },
    registration: {
      rootIdentity: sha('root'),
      rootDefinitionDigest: sha('definition'),
      deviceScopeRef: device,
      inventoryDigest: sha('inventory'),
      registrationSetDigest: sha(instances.map((x) => x.instanceId).sort()),
      instances,
    },
    instances: instances.map((x) => ({
      ...x,
      origin: 'foreign-controller',
      state: [
        'canonical-producer',
        'generic-direct',
        'shared-transaction',
        'native-main-dispatch',
      ].includes(x.entryId)
        ? 'GUARDED'
        : 'NATIVE_NAMESPACE_DENIED',
    })),
    namespaceOwnership: {
      'bulk-report-sync': 'foreign-controller',
      'reserved-bundle': 'foreign-controller',
      'private-report-files': 'foreign-controller',
      'external-subtree-publishers': 'foreign-controller',
    },
  };
  const controller = new ManagedPublicationController(store, 'plugin', account, device, current);
  const driver = new ManagedCoverageDriver(store, 'plugin', account, controller, profile, current);
  return {
    controller,
    driver,
    profile,
    store,
    account,
    db,
    current,
    revoke: () => {
      live = false;
    },
  };
}
it('missing role cannot create a trusted fixed registration', async () => {
  const f = await fixture();
  f.profile.registration.instances = f.profile.registration.instances.slice(0,-1);
  expect(
    () =>
      new ManagedCoverageDriver(f.store, 'plugin', f.account, f.controller, f.profile, f.current),
  ).toThrow('PROFILE');
});
it('actual quiesce/install retains UNKNOWN and does not turn missing foreign source into zero', async () => {
  const f = await fixture();
  await f.driver.quiesce();
  await expect(f.driver.switchRelease('g1', 0)).rejects.toThrow('FOREIGN_SOURCE_UNSUPPORTED');
  const s = await f.driver.status();
  expect(s.state).toBe('UNKNOWN');
  expect(s.releaseSequence).toBe(0);
  expect(s.lifecycleSequence).toBe(0);
  expect(s.lastVerified).toBeNull();
  expect(s.usedGenerations).toEqual(['g1']);
  expect((await f.controller.inspect()).state).toBe('INSTALLED');
  await expect(f.driver.switchRelease('g1', 0)).rejects.toThrow('GENERATION');
  expect(() => f.driver.requireReady()).toThrow('SOURCE_UNSUPPORTED');
});
it('independent counters reject an observation gap before installation', async () => {
  const f = await fixture();
  await expect(f.driver.switchRelease('g1', 2)).rejects.toThrow('SEQUENCE_GAP');
  expect((await f.driver.status()).usedGenerations).toEqual([]);
});
it('raw JSON receipt and absent native root cannot acquire production authority', async () => {
  const f = await fixture();
  expect(() => readManagedEnrollmentReceipt(JSON.parse('{}'), f.controller)).toThrow(
    'ENROLLMENT_RECEIPT',
  );
  const account = {};
  expect(resolveControlledPublicationRoot(account, account, f.current)).toBeUndefined();
  f.revoke();
  expect(() => resolveControlledPublicationRoot(account, account, f.current)).toThrow(
    'OWNER_REVOKED',
  );
});
it('owned source cannot call a retired business decision its own receipt', async () => {
  const f = await fixture();
  for (const x of f.profile.instances)
    if (x.entryId === 'worksheet-ci') {
      x.origin = 'owned-release';
      x.state = 'RETIRED_FENCED';
    }
  expect(
    () =>
      new ManagedCoverageDriver(f.store, 'plugin', f.account, f.controller, f.profile, f.current),
  ).toThrow('RETIREMENT_SOURCE_REQUIRED');
});

it('native effect count reads actual action namespace, preserves old input and rejects corrupt identity', async () => {
  const f = await fixture();
  const { digest } = await import('../restrictedPublicationProtocol.js');
  const insert = (
    state: string,
    plugin = 'plugin',
    action = '12345678-1234-1234-1234-123456789abc',
  ) => {
    const a = {
      schema: 'native-publication-action/v1',
      pluginId: plugin,
      nativeActionId: action,
      actionRevision: 1,
      stateRevision: 1,
      state,
      principalId: 'synthetic-principal',
      partnerId: 'synthetic-partner',
      runId: 'synthetic-run',
      sourceOutputMessageId: 'synthetic-output',
      completedOutputSha256: 'a'.repeat(64),
      effects:
        state === 'APPLIED_VERIFIED'
          ? ['remote-staging-prepare', 'remote-staging-upload', 'remote-transaction']
          : [],
      receiptSha256: 'b'.repeat(64),
    };
    const target =
      'restricted:publication:' +
      digest([
        plugin,
        a.principalId,
        a.partnerId,
        a.runId,
        a.sourceOutputMessageId,
        a.completedOutputSha256,
        'PUBLIC_RELEASE',
      ]);
    f.db
      .prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)')
      .run(
        'native-publication:' + action,
        plugin,
        'target',
        target,
        target,
        digest(a),
        JSON.stringify(a),
        1,
        1,
      );
    return a;
  };
  f.db
    .prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)')
    .run(
      'old-input',
      'plugin',
      'target',
      'restricted:input:old',
      'old',
      'old',
      '{"state":"UNKNOWN"}',
      1,
      1,
    );
  expect(await f.store.unknownNativePublicationEffects('plugin')).toBe(0);
  insert('UNKNOWN');
  expect(await f.store.unknownNativePublicationEffects('plugin')).toBe(1);
  insert('DISPATCHING_UNKNOWN', 'foreign', '22345678-1234-1234-1234-123456789abc');
  expect(await f.store.unknownNativePublicationEffects('plugin')).toBe(1);
  expect(
    f.db.prepare('SELECT payload FROM plugin_task_requests WHERE id=?').get('old-input'),
  ).toEqual({ payload: '{"state":"UNKNOWN"}' });
  f.db
    .prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?')
    .run('{malformed', 'native-publication:12345678-1234-1234-1234-123456789abc');
  await expect(f.store.unknownNativePublicationEffects('plugin')).rejects.toThrow('FACTS_UNKNOWN');
});
it('missing/unknown native action state cannot default to zero and owner revocation blocks read', async () => {
  const f = await fixture();
  f.db
    .prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)')
    .run(
      'native-publication:12345678-1234-1234-1234-123456789abc',
      'plugin',
      'target',
      'restricted:publication:wrong',
      'wrong',
      'wrong',
      '{"schema":"native-publication-action/v1"}',
      1,
      1,
    );
  await expect(f.store.unknownNativePublicationEffects('plugin')).rejects.toThrow('FACTS_UNKNOWN');
  f.revoke();
  await expect(f.store.unknownNativePublicationEffects('plugin')).rejects.toThrow('OWNER_REVOKED');
});
