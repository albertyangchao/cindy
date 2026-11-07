/** tier: unit. Real account SQL + actual authority/IO admission; all deployment/remote effects synthetic.
 * Rule: no JSON issuer, incomplete closed set or stale lifecycle may authorize queue/dispatch.
 * Gap: old Caller only had a preflight callback, with no durable coverage/current IO lease.
 */
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { afterEach, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { controlledPublicationRuntime } from '../restrictedPublicationCaller.js';
import {
  digest,
  publicMarker,
  wireBinding,
  releaseId,
  releasePair,
  orderedPair,
  nativeWireSchema,
  nativeDispatcher,
} from '../restrictedPublicationProtocol.js';
import { createHash } from 'node:crypto';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import {
  ConsumerGuardCoverageAuthority,
  createControlledCoverageController,
  coverageEntries,
  adjacentCoverageEntries,
  type ControlledCoverageReport,
  type ControlledCoverageDriver,
  type CoverageRegistration,
} from '../restrictedPublicationConsumerGuardAuthority.js';
const pureProcess = vi.hoisted(() => ({
  reply: undefined as undefined | ((r: any) => any),
  candidate: undefined as any,
  managedMode: 'normal' as string,
  archiveCandidate: undefined as any,
  syntheticStderr: '' as string,
}));
// Fixed pure-child boundary only; no runtime/provider/network endpoint is contacted.
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    spawn: (...args: any[]) => {
      if (!pureProcess.reply) {
        const real = (actual.spawn as any)(...args);
        real.stderr?.on('data', (b: Buffer) => {
          pureProcess.syntheticStderr = (pureProcess.syntheticStderr + b.toString('utf8')).slice(
            -32000,
          );
        });
        return real;
      }
      const child = new actual.ChildProcess() as any;
      child.stdin = new PassThrough();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.stdio = [
        child.stdin,
        child.stdout,
        child.stderr,
        undefined,
        undefined,
        new PassThrough(),
        new PassThrough(),
      ];
      child.kill = () => {
        queueMicrotask(() => child.emit('close', 1));
        return true;
      };
      let input = '';
      child.stdin.on('data', (b: Buffer) => {
        input += b.toString('utf8');
      });
      let meta: any, nextReply: ((v: any) => void) | undefined;
      child.stdio[5].on('data', (b: Buffer) => {
        const m = JSON.parse(b.toString('utf8'));
        if (!meta) meta = m;
        else nextReply?.(m);
      });
      const request = (operation: string, payload: any) =>
        new Promise<any>((resolve, reject) => {
          if (!meta) return reject(Error('NO_MAIN_JOB'));
          const m = {
            schema: meta.schema,
            jobId: meta.jobId,
            sequence: (meta.sequence ?? -1) + 1,
            nonce: pureProcess.managedMode === 'wrong-nonce' ? '0'.repeat(64) : meta.nonce,
            operation,
            payload,
          };
          nextReply = (r) => {
            meta.sequence = r.sequence;
            meta.nonce = r.nextNonce;
            resolve(r.result);
          };
          child.stdio[6].emit('data', Buffer.from(JSON.stringify(m) + '\n'));
        });
      child.stdin.on('finish', () =>
        queueMicrotask(async () => {
          try {
            const inputRequest = JSON.parse(input);
            if (meta) {
              await request('loaded', { bindingSha256: meta.bindingSha256, entryId: meta.entryId });
              await request('observe', {});
              const candidate = structuredClone(pureProcess.candidate);
              const claim = await request('claim', {
                entryId: 'canonical-producer',
                operationId: 'queue:' + candidate.manifest.artifact_sha256,
              });
              await request('assert_current', { claimId: claim.claim_id });
              if (pureProcess.managedMode === 'wrong-scope')
                candidate.manifest.artifact_relative =
                  'core/imessage/imessage-' + '0'.repeat(32) + '.html';
              if (pureProcess.managedMode === 'duplicate-claim')
                await request('claim', {
                  entryId: 'canonical-producer',
                  operationId: 'queue:' + candidate.manifest.artifact_sha256,
                });
              if (pureProcess.managedMode === 'disconnect') {
                child.emit('close', 1);
                return;
              }
              await request('queue-write', { claimId: claim.claim_id, candidate });
              if (pureProcess.archiveCandidate)
                await request('queue-archive', {
                  claimId: claim.claim_id,
                  candidate: pureProcess.archiveCandidate,
                });
              await request('finish', { claimId: claim.claim_id, outcome: 'COMPLETE' });
            }
            child.stdout.emit(
              'data',
              Buffer.from(JSON.stringify(pureProcess.reply!(inputRequest))),
            );
            child.emit('close', 0);
          } catch {
            child.emit('close', 1);
          }
        }),
      );
      return child;
    },
  };
});
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const dbs: Database.Database[] = [];
afterEach(() => {
  pureProcess.reply = undefined;
  pureProcess.candidate = undefined;
  pureProcess.managedMode = 'normal';
  pureProcess.archiveCandidate = undefined;
  for (const db of dbs.splice(0)) db.close();
});
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
function fixture(change?: (r: ControlledCoverageReport) => void) {
  const sqlite = new Database(':memory:');
  dbs.push(sqlite);
  sqlite.exec(
    'CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key))',
  );
  // Unrelated historical iMessage/native UNKNOWN is outside this coverage namespace and remains byte-exact.
  sqlite
    .prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)')
    .run(
      'old-unknown',
      'plugin',
      'target',
      'restricted:input:old',
      'old',
      'old',
      '{"state":"UNKNOWN","untouched":true}',
      3,
      1,
    );
  const original = JSON.stringify(
    sqlite.prepare('SELECT * FROM plugin_task_requests WHERE id=?').get('old-unknown'),
  );
  const db = { drizzle: drizzle(sqlite) } as unknown as DbClient;
  let owner = true,
    connected = true,
    time = 1000,
    fence = '',
    switches = 0;
  const account = sha('synthetic-account');
  const current = () => {
    if (!owner) throw Error('OWNER_CHANGED');
  };
  const store = createRestrictedPartnerStore(db, current);
  const registration: CoverageRegistration = {
    rootIdentity: sha('synthetic-root'),
    rootDefinitionDigest: sha('synthetic-definition'),
    deviceScopeRef: sha('synthetic-device'),
    inventoryDigest: sha('registered-full-inventory'),
    registrationSetDigest: sha(
      JSON.stringify(coverageEntries.map((_, i) => 'synthetic-instance-' + i).sort()),
    ),
    instances: coverageEntries.map((entryId, i) => ({
      instanceId: 'synthetic-instance-' + i,
      entryId,
      entryDefinitionDigest: sha(entryId),
    })),
  };
  let quiesceHook: (() => Promise<void>) | undefined, switchHook: (() => Promise<void>) | undefined;
  const driver: ControlledCoverageDriver = {
    issuerId: 'synthetic-managed-controller',
    accountScopeRef: account,
    registration,
    assertCurrent(value) {
      if (!connected || (value && value !== fence)) throw Error('CONTROLLER_OFFLINE_OR_CHANGED');
    },
    async quiesce() {
      fence = '';
      await quiesceHook?.();
    },
    async switchRelease(generation, sequence) {
      switches++;
      if (switches > 1) registration.rootIdentity = sha('synthetic-root-' + generation);
      await switchHook?.();
      fence = 'synthetic-fence-' + sha(generation);
      const r: ControlledCoverageReport = {
        releaseGeneration: generation,
        releaseSequence: switches,
        lifecycleSequence: sequence + 1,
        fenceRef: fence,
        enrollmentReceiptId: 'synthetic-closed-registration',
        oldGenerationAdmissions: { unresolved: 0, fenceReceiptId: 'synthetic-old-fence' },
        unknownNativeEffects: 0,
        members: registration.instances.map((m) => ({
          ...m,
          launchAuthorityId: 'synthetic-managed-controller',
          admissionReceiptId: 'synthetic-admission-' + m.instanceId,
          releaseGeneration: generation,
          guardSourceIdentity: registration.rootIdentity,
          state: m.entryId === 'worksheet-ci' ? 'RETIRED_FENCED' : 'GUARDED',
          effectFenceRevision: 1,
          dispositionReceiptId:
            m.entryId === 'worksheet-ci' ? 'synthetic-retirement-receipt' : null,
        })),
        exclusions: adjacentCoverageEntries.map((entryId) => ({
          entryId,
          namespace: 'native-publication',
          fenceReceiptId: 'synthetic-exclusion-' + entryId,
          definitionDigest: sha('namespace-' + entryId),
          fenceRevision: 1,
        })),
      };
      change?.(r);
      return r;
    },
  };
  const controller = createControlledCoverageController(driver);
  const create = () =>
    new ConsumerGuardCoverageAuthority(store, 'plugin', account, current, controller, () => time);
  const authority = create();
  const root = registration.rootIdentity;
  const read = async () => authority.readCurrent(root, authority.freshChallenge(root));
  return {
    sqlite,
    store,
    db,
    authority,
    account,
    registration,
    driver,
    create,
    root,
    read,
    tick: (t: number) => {
      time = t;
    },
    revoke: () => {
      owner = false;
    },
    disconnect: () => {
      connected = false;
    },
    reconnect: () => {
      connected = true;
    },
    quiescing: (f: () => Promise<void>) => {
      quiesceHook = f;
    },
    installing: (f: () => Promise<void>) => {
      switchHook = f;
    },
    switches: () => switches,
    admissions: () =>
      sqlite
        .prepare(
          "SELECT payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-coverage-admission/v1'",
        )
        .all() as Array<{ payload: string }>,
    preserved: () =>
      expect(
        JSON.stringify(
          sqlite.prepare('SELECT * FROM plugin_task_requests WHERE id=?').get('old-unknown'),
        ),
      ).toBe(original),
  };
}
it('no controller or JSON/fake issuer can register production READY; scope is bound to the account store', async () => {
  const f = fixture();
  const unsupported = new ConsumerGuardCoverageAuthority(f.store, 'plugin', f.account, () => {});
  expect(await unsupported.status()).toBe('UNSUPPORTED');
  await expect(unsupported.switchGeneration('generation-1')).rejects.toThrow(
    'CONTROLLER_UNSUPPORTED',
  );
  for (const bad of [
    { issuerId: 'fake', closedEnrollment: true },
    Object.create(null),
    { readCurrent: () => ({ state: 'READY' }) },
  ])
    expect(
      () => new ConsumerGuardCoverageAuthority(f.store, 'plugin', f.account, () => {}, bad),
    ).toThrow('CONTROLLER_UNSUPPORTED');
  expect(() => createControlledCoverageController({ issuerId: 'JSON-only' } as any)).toThrow(
    'CONTROLLER_UNSUPPORTED',
  );
  expect(
    () =>
      new ConsumerGuardCoverageAuthority(
        f.store,
        'plugin',
        sha('different-account'),
        () => {},
        createControlledCoverageController(f.driver),
      ),
  ).toThrow('SCOPE_INVALID');
  f.preserved();
});
it('controlled lifecycle stores exact complete coverage and one-use root challenge; retirement/exclusions remain enforced', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  const n = f.authority.freshChallenge(f.root),
    proof = await f.authority.readCurrent(f.root, n);
  expect(proof.members).toHaveLength(7);
  expect(proof.closedEnrollment).toBe(true);
  expect(proof.expiresAt - proof.issuedAt).toBeLessThanOrEqual(30000);
  expect(proof.oldGenerationAdmissions).toBe(0);
  expect(Object.keys(proof.members[0]).sort()).toEqual(
    [
      'instanceId',
      'entryId',
      'launchAuthorityId',
      'admissionReceiptId',
      'releaseGeneration',
      'guardSourceIdentity',
      'entryDefinitionDigest',
      'state',
      'effectFenceRevision',
    ].sort(),
  );
  await expect(f.authority.readCurrent(f.root, n)).rejects.toThrow('CHALLENGE_INVALID');
  await expect(
    f.authority.readCurrent(sha('another-root'), f.authority.freshChallenge(f.root)),
  ).rejects.toThrow('CHALLENGE_INVALID');
  let effects = 0;
  for (const kind of [
    'stage',
    'remote-staging-prepare',
    'remote-staging-upload',
    'remote-transaction',
  ] as const)
    await f.authority.withAdmission(f.root, 'one-action', kind, async (permit) => {
      permit.assertCurrent();
      effects++;
    });
  expect(effects).toBe(4);
  await expect(
    f.authority.withAdmission(f.root, 'one-action', 'stage', async () => {
      effects++;
    }),
  ).rejects.toThrow('ALREADY_CLAIMED');
  expect(effects).toBe(4);
  expect(await f.authority.status()).toBe('READY');
  expect(f.admissions().every((r) => JSON.parse(r.payload).state === 'COMPLETE')).toBe(true);
  f.preserved();
});
for (const [name, change] of [
  [
    'missing member',
    (r: ControlledCoverageReport) => {
      r.members.pop();
    },
  ],
  [
    'extra instance',
    (r: ControlledCoverageReport) => {
      r.members.push({ ...r.members[0], instanceId: 'extra' });
    },
  ],
  [
    'old generation',
    (r: ControlledCoverageReport) => {
      r.members[0].releaseGeneration = 'old';
    },
  ],
  [
    'active old admissions',
    (r: ControlledCoverageReport) => {
      r.oldGenerationAdmissions.unresolved = 1;
    },
  ],
  [
    'unknown absent instead of zero',
    (r: ControlledCoverageReport) => {
      delete (r as any).unknownNativeEffects;
    },
  ],
  [
    'event sequence gap',
    (r: ControlledCoverageReport) => {
      r.lifecycleSequence++;
    },
  ],
  [
    'release sequence gap',
    (r: ControlledCoverageReport) => {
      r.releaseSequence++;
    },
  ],
  [
    'retired without receipt',
    (r: ControlledCoverageReport) => {
      r.members.find((m) => m.state === 'RETIRED_FENCED')!.dispositionReceiptId = null;
    },
  ],
  [
    'unproved adjacent namespace',
    (r: ControlledCoverageReport) => {
      r.exclusions.pop();
    },
  ],
] as const)
  it('controlled switch refuses ' + name + ' and preserves unknown evidence', async () => {
    const f = fixture(change);
    await expect(f.authority.switchGeneration('generation-1')).rejects.toThrow('COVERAGE_');
    expect(await f.authority.status()).toBe('UNKNOWN');
    await expect(f.read()).rejects.toThrow('NOT_READY');
    f.preserved();
  });
it('QUIESCING synchronously revokes an existing lease before controller mutation and before queued IO', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  const acquired = deferred(),
    release = deferred();
  let dispatched = 0;
  const pending = f.authority.withAdmission(f.root, 'staged-action', 'stage', async (permit) => {
    acquired.resolve();
    await release.promise;
    permit.assertCurrent();
    dispatched++;
  });
  await acquired.promise;
  const mutation = f.authority.invalidate();
  await expect(f.read()).rejects.toThrow();
  release.resolve();
  await mutation;
  await expect(pending).rejects.toThrow('LEASE_REVOKED');
  expect(dispatched).toBe(0);
  expect(JSON.parse(f.admissions()[0].payload).state).toBe('UNKNOWN');
  f.preserved();
});
it('already-dispatched late completion remains UNKNOWN, cannot resend or cross into a new release', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  const started = deferred(),
    finish = deferred();
  let effects = 0;
  const run = f.authority.withAdmission(
    f.root,
    'remote-action',
    'remote-transaction',
    async (permit) => {
      permit.assertCurrent();
      effects++;
      started.resolve();
      await finish.promise;
      permit.assertCurrent();
    },
  );
  await started.promise;
  await f.authority.invalidate('REVOKED');
  finish.resolve();
  await expect(run).rejects.toThrow('LEASE_REVOKED');
  expect(effects).toBe(1);
  await expect(
    f.authority.withAdmission(f.root, 'remote-action', 'remote-transaction', async () => {
      effects++;
    }),
  ).rejects.toThrow('NOT_READY');
  await expect(f.authority.switchGeneration('generation-2')).rejects.toThrow(
    'UNRESOLVED_ADMISSION',
  );
  expect(effects).toBe(1);
  expect(JSON.parse(f.admissions()[0].payload).state).toBe('UNKNOWN');
  f.preserved();
});
it('concurrent duplicate claims dispatch once and release error never masks the original IO exception', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  let n = 0;
  const results = await Promise.allSettled(
    [1, 2].map(() =>
      f.authority.withAdmission(f.root, 'same-action', 'stage', async (p) => {
        p.assertCurrent();
        n++;
      }),
    ),
  );
  expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  expect(n).toBe(1);
  f.quiescing(async () => {
    throw Error('CLEANUP_UNKNOWN');
  });
  await expect(
    f.authority.withAdmission(f.root, 'failure-action', 'remote-staging-prepare', async () => {
      throw Error('ORIGINAL_IO_FAILURE');
    }),
  ).rejects.toThrow('ORIGINAL_IO_FAILURE');
  expect(f.admissions().filter((r) => JSON.parse(r.payload).state === 'UNKNOWN')).toHaveLength(1);
  f.preserved();
});
it('restart/rollback cannot inherit old READY or revive used generations; new controlled generation is required', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  const restarted = f.create();
  expect(await restarted.status()).toBe('UNKNOWN');
  await expect(f.read()).rejects.toThrow('NOT_READY');
  await expect(restarted.switchGeneration('generation-1')).rejects.toThrow('GENERATION_REUSED');
  await restarted.switchGeneration('generation-2');
  expect(await restarted.status()).toBe('READY');
  await expect(restarted.switchGeneration('generation-1')).rejects.toThrow('GENERATION_REUSED');
  const s = f.sqlite
    .prepare(
      "SELECT count(*) AS n FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-coverage-state/v1'",
    )
    .get() as { n: number };
  expect(s.n).toBeGreaterThan(3);
  f.preserved();
});
it('expiry, backwards clock, owner change, disconnect and descriptor drift cannot leave a positive IO lease', async () => {
  for (const cause of ['expiry', 'backwards', 'owner', 'disconnect', 'definition'] as const) {
    const f = fixture();
    await f.authority.switchGeneration('generation-1');
    let n = 0;
    await expect(
      f.authority.withAdmission(f.root, 'test-' + cause, 'stage', async (p) => {
        if (cause === 'expiry') f.tick(31000);
        if (cause === 'backwards') f.tick(999);
        if (cause === 'owner') f.revoke();
        if (cause === 'disconnect') f.disconnect();
        if (cause === 'definition')
          (f.registration.instances[0] as any).entryDefinitionDigest = sha('drift');
        p.assertCurrent();
        n++;
      }),
    ).rejects.toThrow();
    expect(n).toBe(0);
    f.preserved();
  }
});
it('late switch completion cannot reopen after a concurrent invalidation; damaged SQL is never default-zero evidence', async () => {
  const f = fixture(),
    entered = deferred(),
    release = deferred();
  f.installing(async () => {
    entered.resolve();
    await release.promise;
  });
  const changing = f.authority.switchGeneration('generation-1');
  await entered.promise;
  const invalidation = f.authority.invalidate('UNKNOWN');
  release.resolve();
  await expect(changing).rejects.toThrow('LEASE_REVOKED');
  await invalidation;
  expect(await f.authority.status()).toBe('UNKNOWN');
  f.sqlite
    .prepare(
      "UPDATE plugin_task_requests SET payload=? WHERE json_extract(payload,'$.schema')='publication-coverage-state/v1'",
    )
    .run('{"broken":true}');
  await expect(f.read()).rejects.toThrow('RECEIPT_UNKNOWN');
  f.preserved();
});

// Exercise the actual Caller queue/three dispatch methods with real tmp files and account SQL.
// Only the already-accepted pure Python contract process and external transport are synthetic here.
async function callerFixture(f: ReturnType<typeof fixture>, beforeIO?: () => Promise<void>) {
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'coverage-caller-')));
  const root = path.join(dir, 'root'),
    artifacts = path.join(dir, 'artifacts'),
    dispatch = path.join(dir, 'dispatch');
  await Promise.all(
    [root, artifacts, dispatch, path.join(dir, 'queue')].map((p) => mkdir(p, { mode: 0o700 })),
  );
  const files: Record<string, string> = {};
  for (const rel of [
    'scripts/publish_generic_html_direct.py',
    'scripts/publish_worksheet_html.py',
    'bridge_core/native_html_release.py',
    'bridge_core/publish_html.py',
    'bridge_core/report_publish_queue.py',
    'bridge_core/html_contract.py',
    'bridge_core/research_artifacts.py',
    'config/html_ui_contract.json',
    'config/reserved_html_owners.json',
    'config/bridge_shell_builders.json',
    'config/artifact_publish_policy.json',
  ]) {
    await mkdir(path.dirname(path.join(root, rel)), { recursive: true, mode: 0o700 });
    await writeFile(path.join(root, rel), 'synthetic pinned closure', { mode: 0o600 });
    files[rel] = sha('synthetic pinned closure');
  }
  const python = path.join(dir, 'synthetic-interpreter');
  await writeFile(python, 'not executed: pure child mocked', { mode: 0o600 });
  const a: any = {
    nativeActionId: '00000000-0000-4000-8000-000000000001',
    actionRevision: 1,
    grantId: 'synthetic-grant',
    grantRevision: 1,
    domainId: 'synthetic-domain',
    principalId: 'synthetic-principal',
    partnerId: 'synthetic-partner',
    connectionId: 'synthetic-connection',
    generation: 'synthetic-generation',
    chatId: 'synthetic-chat',
    eventId: 'synthetic-event',
    runId: 'synthetic-run',
    effectSlot: 'reply',
    epoch: 1,
    resourceFingerprint: sha('resources'),
    completedOutputSha256: sha('synthetic result'),
    artifactSha256: sha('synthetic html'),
    publisherBindingSha256: sha('binding'),
    artifactRelative: 'pending',
    expiresAt: Date.now() + 60000,
    effects: [],
  };
  a.artifactRelative =
    'core/imessage/imessage-' + publicMarker(wireBinding(a)).binding_digest.slice(0, 32) + '.html';
  await mkdir(path.dirname(path.join(artifacts, a.artifactRelative)), {
    recursive: true,
    mode: 0o700,
  });
  await writeFile(path.join(artifacts, a.artifactRelative), 'synthetic html', { mode: 0o600 });
  const metadata = {
    provenance: publicMarker(wireBinding(a)),
    publisher_binding_sha256: a.publisherBindingSha256,
  };
  const metaRaw = JSON.stringify(metadata);
  await writeFile(path.join(artifacts, a.artifactRelative.slice(0, -5) + '.json'), metaRaw, {
    mode: 0o600,
  });
  pureProcess.candidate = {
    expectedBeforeSha256: null,
    manifest: {
      schema_version: 1,
      state: 'queued',
      queued_at: new Date().toISOString(),
      artifact: path.join(artifacts, a.artifactRelative),
      artifact_relative: a.artifactRelative,
      artifact_sha256: a.artifactSha256,
      public_url: null,
      candidate_public_url: 'https://synthetic.invalid/reports/' + a.artifactRelative,
      source: 'bluebubbles-connect',
      publisher_metadata: path.posix.basename(a.artifactRelative.slice(0, -5) + '.json'),
      publisher_metadata_sha256_at_queue: sha(metaRaw),
      publisher_binding_sha256: a.publisherBindingSha256,
      template_family: 'home-kb',
      template_variant: 'plain',
      template_producer: {},
      ui_contract: {},
      dispatcher: null,
      dispatcher_status: 'staged-not-deployed',
    },
  };
  let sent = 0,
    stages = 0;
  pureProcess.reply = (r) => {
    if (r.operation === 'managed-contract')
      return pureProcess.managedMode === 'old-root'
        ? { schema: 'old-root' }
        : {
            schema: 'publication-managed-job/v1',
            nativeQueueIO: 'main-only',
            controlReadFd: 5,
            controlWriteFd: 6,
          };
    if (r.operation === 'contract')
      return { schema: nativeWireSchema, generation: 'string', dispatcher: nativeDispatcher };
    if (r.operation === 'stage') {
      stages++;
      return {};
    }
    if (r.operation === 'inspect')
      return {
        artifactRelative: a.artifactRelative,
        artifactSha256: a.artifactSha256,
        publicMarker: publicMarker(wireBinding(a)),
        publisherBindingSha256: a.publisherBindingSha256,
      };
    if (r.operation === 'commands')
      return {
        host: 'synthetic-publisher',
        releaseId: releaseId(wireBinding(a)),
        publicUrl: 'https://synthetic.invalid/reports/' + a.artifactRelative,
        orderedPair: orderedPair(releasePair(wireBinding(a)), wireBinding(a)),
        bootstrap: 'synthetic prepare',
        upload: 'synthetic upload',
        transaction: 'synthetic transaction',
        receipt: 'synthetic receipt',
        verify: 'synthetic verify',
      };
    throw Error('UNEXPECTED_PURE_OPERATION');
  };
  const pin = {
    root,
    artifactRoot: artifacts,
    queueRoot: path.join(dir, 'queue'),
    dispatchRoot: dispatch,
    publicOrigin: 'https://synthetic.invalid',
    sourceIdentity: sha('closure'),
    files,
    python: { path: python, sha256: sha('not executed: pure child mocked') },
    assertConsumerGuards: async () => {},
    consumerCoverage: f.authority,
    consumerRootIdentity: f.root,
  };
  f.registration.rootDefinitionDigest = digest([
    pin.sourceIdentity,
    pin.root,
    pin.artifactRoot,
    pin.queueRoot,
    pin.dispatchRoot,
    pin.publicOrigin,
    files,
    pin.python,
  ]);
  const runtime = controlledPublicationRuntime(
    pin,
    { effectCurrent: () => {}, readCurrent: () => {} },
    {
      async execute(_exe, _args, current) {
        await beforeIO?.();
        current();
        sent++;
        return { stdout: Buffer.alloc(0) };
      },
      async readback() {
        throw Error('NOT_AN_EFFECT_TEST');
      },
    },
  );
  return {
    runtime,
    a,
    pin,
    sent: () => sent,
    stages: () => stages,
    dir,
    queued: async () => {
      try {
        return JSON.parse(
          await readFile(path.join(dir, 'queue', a.artifactSha256 + '.json'), 'utf8'),
        );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
        throw error;
      }
    },
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}
it('actual Caller stages once and composes real coverage admission on every fixed dispatch, with no callback-only authority', async () => {
  const f = fixture();
  const c = await callerFixture(f);
  await f.authority.switchGeneration('generation-1');
  try {
    expect(() =>
      controlledPublicationRuntime(
        {
          ...c.pin,
          consumerCoverage: { readCurrent: async () => ({ closedEnrollment: true }) } as any,
        },
        { effectCurrent: () => {}, readCurrent: () => {} },
      ),
    ).toThrow('CALLER_DENIED');
    await c.runtime.stage(c.a, 'synthetic result', {
      stageBind: async () => c.a,
      beforeEffect: async () => {},
      settle: async () => c.a,
    });
    for (const effect of [
      'remote-staging-prepare',
      'remote-staging-upload',
      'remote-transaction',
    ] as const) {
      c.a.effects.push(effect);
      await c.runtime.dispatch(c.a, effect);
    }
    expect(c.stages()).toBe(1);
    expect((await c.queued()).artifact_sha256).toBe(c.a.artifactSha256);
    expect(c.sent()).toBe(3);
    expect(f.admissions()).toHaveLength(4);
    await f.authority.switchGeneration('generation-2');
    expect(await f.authority.status()).toBe('READY');
    f.preserved();
  } finally {
    await c.cleanup();
  }
});
for (const blocked of [
  'remote-staging-prepare',
  'remote-staging-upload',
  'remote-transaction',
] as const)
  it(
    'actual Caller ' +
      blocked +
      ' denies IO after a queued lifecycle revoke, preserves durable UNKNOWN and never retries',
    async () => {
      const f = fixture();
      let kind = '';
      const c = await callerFixture(f, async () => {
        if (kind === blocked) await f.authority.invalidate('REVOKED');
      });
      await f.authority.switchGeneration('generation-1');
      try {
        let prior = 0;
        for (const effect of [
          'remote-staging-prepare',
          'remote-staging-upload',
          'remote-transaction',
        ] as const) {
          kind = effect;
          c.a.effects.push(effect);
          if (effect === blocked) {
            await expect(c.runtime.dispatch(c.a, effect)).rejects.toThrow('LEASE_REVOKED');
            break;
          }
          await c.runtime.dispatch(c.a, effect);
          prior++;
        }
        expect(c.sent()).toBe(prior);
        expect(JSON.parse(f.admissions().at(-1)!.payload).state).toBe('UNKNOWN');
        await expect(c.runtime.dispatch(c.a, blocked)).rejects.toThrow();
        expect(c.sent()).toBe(prior);
        f.preserved();
      } finally {
        await c.cleanup();
      }
    },
  );

it('a transient disconnect cannot revive old coverage after reconnect; zero-evidence read stays closed', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  f.disconnect();
  await expect(f.read()).rejects.toThrow('CONTROLLER_OFFLINE');
  f.reconnect();
  expect(await f.authority.status()).toBe('UNKNOWN');
  await expect(f.read()).rejects.toThrow('NOT_READY');
  await f.authority.switchGeneration('generation-2');
  expect(await f.authority.status()).toBe('READY');
  f.preserved();
});
it('actual Caller cannot reuse coverage for a different root definition or mutate pins during awaited IO', async () => {
  const f = fixture();
  let c!: Awaited<ReturnType<typeof callerFixture>>;
  c = await callerFixture(f, async () => {
    c.pin.publicOrigin = 'https://different.invalid';
  });
  await f.authority.switchGeneration('generation-1');
  try {
    c.a.effects.push('remote-staging-prepare');
    await expect(c.runtime.dispatch(c.a, 'remote-staging-prepare')).rejects.toThrow(
      'CALLER_DENIED',
    );
    expect(c.sent()).toBe(0);
    expect(JSON.parse(f.admissions()[0].payload).state).toBe('UNKNOWN');
    f.preserved();
  } finally {
    await c.cleanup();
  }
});

it('an exact 30-second challenge is expired and incomplete persisted READY cannot mint a lease', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  const nonce = f.authority.freshChallenge(f.root);
  f.tick(31000);
  await expect(f.authority.readCurrent(f.root, nonce)).rejects.toThrow('CHALLENGE_INVALID');
  const row = f.sqlite
    .prepare(
      "SELECT id,payload FROM plugin_task_requests WHERE json_extract(payload,'$.state')='READY' AND json_extract(payload,'$.schema')='publication-coverage-state/v1' ORDER BY revision DESC LIMIT 1",
    )
    .get() as { id: string; payload: string };
  const damaged = JSON.parse(row.payload);
  damaged.releaseGeneration = null;
  f.sqlite
    .prepare('UPDATE plugin_task_requests SET payload=? WHERE id=?')
    .run(JSON.stringify(damaged), row.id);
  // The damaged row may be an immutable audit entry; damage the current row as well, never accept either as evidence.
  f.sqlite
    .prepare(
      "UPDATE plugin_task_requests SET payload=? WHERE json_extract(payload,'$.state')='READY' AND json_extract(payload,'$.schema')='publication-coverage-state/v1'",
    )
    .run(JSON.stringify(damaged));
  await expect(f.read()).rejects.toThrow('RECEIPT_UNKNOWN');
  f.preserved();
});

it('pinned Core source ABI preserves exact opaque 512-byte generation and rejects controls/over-budget values before a switch', async () => {
  const f = fixture();
  for (const value of ['x'.repeat(513), 'bad\u0000generation', 'bad\u0085generation'])
    await expect(f.authority.switchGeneration(value)).rejects.toThrow('GENERATION_INVALID');
  expect(f.switches()).toBe(0);
  const generation = 'x'.repeat(512);
  await f.authority.switchGeneration(generation);
  const proof = await f.read();
  expect(proof.releaseGeneration).toBe(generation);
  expect(typeof proof.oldGenerationAdmissions).toBe('number');
  f.preserved();
});

for (const mode of [
  'wrong-nonce',
  'wrong-scope',
  'duplicate-claim',
  'disconnect',
  'old-root',
] as const)
  it(
    'managed fixed-child ' + mode + ' cannot write a native queue or relaunch an unknown job',
    async () => {
      const f = fixture();
      const c = await callerFixture(f);
      await f.authority.switchGeneration('generation-1');
      pureProcess.managedMode = mode;
      try {
        await expect(
          c.runtime.stage(c.a, 'synthetic result', {
            stageBind: async () => c.a,
            beforeEffect: async () => {},
            settle: async () => c.a,
          }),
        ).rejects.toThrow();
        expect(await c.queued()).toBeUndefined();
        expect(c.sent()).toBe(0);
        const jobs = f.sqlite
          .prepare(
            "SELECT payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-managed-job/v1'",
          )
          .all() as Array<{ payload: string }>;
        if (mode === 'old-root') expect(jobs).toHaveLength(0);
        else expect(jobs.some((r) => JSON.parse(r.payload).state === 'UNKNOWN')).toBe(true);
        await expect(
          c.runtime.stage(c.a, 'synthetic result', {
            stageBind: async () => c.a,
            beforeEffect: async () => {},
            settle: async () => c.a,
          }),
        ).rejects.toThrow();
        expect(await c.queued()).toBeUndefined();
        f.preserved();
      } finally {
        await c.cleanup();
      }
    },
  );
it('observed same-generation facts cannot relatch on a second read; original verified report/counters survive rejection', async () => {
  const f = fixture();
  await f.authority.switchGeneration('generation-1');
  const first = await f.read();
  const definition = f.registration.instances[0].entryDefinitionDigest;
  (f.registration.instances[0] as any).entryDefinitionDigest = sha('unauthorized-drift');
  await expect(f.read()).rejects.toThrow('FACTS_CHANGED');
  (f.registration.instances[0] as any).entryDefinitionDigest = definition;
  await expect(f.read()).rejects.toThrow('NOT_READY');
  expect(await f.authority.status()).toBe('UNKNOWN');
  const rows = f.sqlite
    .prepare(
      "SELECT payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-coverage-state/v1'",
    )
    .all() as Array<{ payload: string }>;
  expect(
    rows
      .map((r) => JSON.parse(r.payload))
      .filter((r) => r.state === 'UNKNOWN')
      .every(
        (r) =>
          r.report.releaseGeneration === 'generation-1' &&
          r.releaseSequence === first.releaseSequence &&
          r.lifecycleSequence === first.lifecycleSequence,
      ),
  ).toBe(true);
  await f.authority.switchGeneration('generation-2');
  expect(await f.authority.status()).toBe('READY');
  f.preserved();
});
it('repeated rejected sequence changes retain the last verified baseline and never become READY', async () => {
  const f = fixture((r) => {
    if (r.releaseGeneration !== 'generation-1') r.releaseSequence++;
  });
  await f.authority.switchGeneration('generation-1');
  for (const gen of ['generation-2', 'generation-3'])
    await expect(f.authority.switchGeneration(gen)).rejects.toThrow('COVERAGE_UNKNOWN');
  expect(await f.authority.status()).toBe('UNKNOWN');
  await expect(f.read()).rejects.toThrow('NOT_READY');
  const rows = f.sqlite
    .prepare(
      "SELECT payload FROM plugin_task_requests WHERE json_extract(payload,'$.schema')='publication-coverage-state/v1'",
    )
    .all() as Array<{ payload: string }>;
  expect(
    rows
      .map((r) => JSON.parse(r.payload))
      .filter((r) => r.state === 'UNKNOWN')
      .every(
        (r) =>
          r.report.releaseGeneration === 'generation-1' &&
          r.releaseSequence === 1 &&
          r.lifecycleSequence === 1,
      ),
  ).toBe(true);
  f.preserved();
});

it('actual Main queue archival preserves predecessor failure evidence and durable successor before the canonical move', async () => {
  const f = fixture();
  const c = await callerFixture(f);
  await f.authority.switchGeneration('generation-1');
  const oldSha = 'd'.repeat(64),
    m = pureProcess.candidate.manifest;
  m.consecutive_failures = 2;
  m.failing_since = '2020-01-01T00:00:00Z';
  const old = {
    ...m,
    artifact_sha256: oldSha,
    queued_at: '2020-01-01T00:00:00Z',
    last_failure: { failed_at: '2020-01-01T00:00:00Z', stage: 'synthetic' },
  };
  const raw = JSON.stringify(old);
  await writeFile(path.join(c.dir, 'queue', oldSha + '.json'), raw, { mode: 0o600 });
  pureProcess.archiveCandidate = { predecessorSha256: oldSha, expectedBeforeSha256: sha(raw) };
  try {
    await c.runtime.stage(c.a, 'synthetic result', {
      stageBind: async () => c.a,
      beforeEffect: async () => {},
      settle: async () => c.a,
    });
    const name =
      path.posix.basename(c.a.artifactRelative, '.html') + '.' + oldSha + '.20200101T000000Z.json';
    const archived = JSON.parse(
      await readFile(path.join(c.dir, 'queue/archive/generic-html', name), 'utf8'),
    );
    expect(archived.state).toBe('superseded');
    expect(archived.consecutive_failures).toBe(2);
    expect(archived.last_failure).toEqual(old.last_failure);
    expect((await c.queued()).consecutive_failures).toBe(2);
    await expect(readFile(path.join(c.dir, 'queue', oldSha + '.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    f.preserved();
  } finally {
    await c.cleanup();
  }
});
