/** Security preflight uses actual SQLite and filesystem checks. No executable,
 * resident, OS census or source receipt is simulated as a positive control. */
import { afterEach, expect, it, vi } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { performance } from 'node:perf_hooks';
import { PassThrough, Writable } from 'node:stream';
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
import { RestrictedPublicationCIProducer, originalCIEffectIdentity,
  originalCIEffectTarget,
  type OriginalCIEffectDescriptor, type OriginalCIEffectObservation } from '../restrictedPublicationCIProducer.js';

const processBoundary = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock('node:child_process', async importOriginal => ({
  ...await importOriginal<typeof import('node:child_process')>(), spawn: processBoundary.spawn,
}));

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const release of cleanup.splice(0).reverse()) await release();
  vi.restoreAllMocks(); vi.useRealTimers(); processBoundary.spawn.mockReset();
});
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

/** Test value: exercise the actual Main listener/producer, pinned files and
 * SQLite journal through their public entries. Only spawn and its protocol
 * counterpart are isolated OS effects; these tests do not claim a real kernel
 * peer or an authoritative census. Existing preflight tests never covered a
 * long observation between two sessions, cumulative budgets or stale handles.
 * Minimal input: one peer and (for CI) the fixed prepare/start/cleanup plan.
 * Tier: unit. Virtual clocks replace the runner's minute-scale wait. */
const runnerIdentity = { repository: 'albertyangchao/core-bridge', route: 'valerie-bridge',
  runId: 41, attempt: 1, jobId: 42, headSha: 'a'.repeat(40), workflowPath: '.github/workflows/coverage.yml',
  workflowBlob: 'b'.repeat(40), goldenSha256: digest('golden') };
const runnerEffects: OriginalCIEffectDescriptor[] = ['jit-prepare', 'jit-register-start', 'jit-cleanup'].map(kind =>
  ({ schema: 'publication-ci-effect/v1', kind: kind as OriginalCIEffectDescriptor['kind'], identity: { ...runnerIdentity } }));
async function heldFixture(ci = false) {
  const f = await fixture(), descriptor = f.profile.owners[0];
  if (ci) Object.assign(descriptor, { ownerId: 'core-jit.bridge-jit-controller', sourceScope: 'REGISTERED_CI_PRODUCER',
    entryScript: 'bridge_core/publication_ci_producer.py', originalEntryScript: 'macmini-jit-controller/start-approved-jit-runner.sh',
    originalArgv: ['/bin/bash', path.join(f.root, 'macmini-jit-controller/start-approved-jit-runner.sh')],
    entryArgv: [f.profile.python.path, '-I', '-B', path.join(f.root, 'bridge_core/publication_ci_producer.py'), 'jit-controller'] });
  const names = [...new Set(['bridge_core/publication_owner_listener.py', 'bridge_core/publication_resident_source.py',
    descriptor.entryScript, descriptor.originalEntryScript, ...(ci ? ['macmini-jit-controller/publication_ci_owner.py'] : [])])];
  const files: Record<string, string> = {};
  for (const name of names) {
    const file = path.join(f.root, name), bytes = Buffer.from('isolated Main wire fixture: ' + name);
    await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    await writeFile(file, bytes, { mode: 0o600 });
    files[name] = createHash('sha256').update(bytes).digest('hex');
  }
  const interpreter = Buffer.from('not executed: isolated spawn boundary');
  await writeFile(f.profile.python.path, interpreter, { mode: 0o600 });
  f.profile.python.sha256 = createHash('sha256').update(interpreter).digest('hex');
  f.profile.files = files; f.profile.sourceDigest = digest(files);
  descriptor.originalBootstrapSha256 = files[descriptor.originalEntryScript];
  const responses = new PassThrough(), child = new EventEmitter();
  let sessionId = '', nonce = '', resumed = false, responseBytes = 0;
  let wake: (() => void) | undefined, probeBytes = 0, partialResponse = false;
  let markWaiting!: () => void;
  const waitStarted = new Promise<void>(resolve => { markWaiting = resolve; });
  const frames: Record<string, any>[] = [];
  const peer = { peerId: 'isolated-original-peer', instanceId: descriptor.instanceId, ownerId: descriptor.ownerId,
    sourceScope: descriptor.sourceScope, entryScript: descriptor.entryScript, originalEntryScript: descriptor.originalEntryScript,
    root: f.root, sourceDigest: f.profile.sourceDigest, definitionDigest: descriptor.definitionDigest,
    process: { processId: 12346, uid: 1000, startIdentity: 'isolated-process-start', executable: f.profile.python.path,
      argv: descriptor.entryArgv, cwd: f.root }, files,
    observation: { state: 'CONNECTED', loadedNonce: null as string | null, nativeWithoutMain: null as string | null,
      activeOperations: 0, unknownOperations: 0, fenceRevision: 0, probe: null as Record<string, unknown> | null,
      ...(ci ? { ciEffect: null as OriginalCIEffectObservation | null } : {}) } };
  const status = (state: string) => ({ state, processId: 12345, runtimeDirectory: f.profile.runtimeDirectory,
    sourceRoot: f.root, sourceDigest: f.profile.sourceDigest, peerCount: frames.some(x => x.method === 'accept') ? 1 : 0,
    policyRevision: 1, policySha256: digest('isolated-policy') });
  const requestNextEffect = () => {
    const sequence = (peer.observation.ciEffect?.sequence ?? 0) + 1;
    const effect = runnerEffects[sequence - 1], effectId = originalCIEffectIdentity(effect);
    peer.observation.ciEffect = { sequence, effectId, descriptorSha256: effectId, descriptor: structuredClone(effect),
      state: 'REQUESTED', admissionId: null, outcome: null, outcomeSha256: null };
  };
  const respond = (frame: Record<string, any>, result: unknown) => {
    nonce = digest(['isolated-response-nonce', frame.seq ?? 0]);
    const bytes = Buffer.from(canonical({ schema: 'resident-owner-listener/v1', sessionId,
      operationId: frame.operationId, binding: frame.binding, seq: frame.seq ?? 0, nextNonce: nonce,
      ok: true, code: null, result }) + '\n');
    const chunk = partialResponse ? bytes.subarray(0, 16) : bytes;
    responseBytes += chunk.length;
    queueMicrotask(() => responses.write(chunk));
  };
  const commands = new Writable({ write(bytes, _encoding, done) {
    try {
      const frame = JSON.parse(bytes.toString()); frames.push(structuredClone(frame));
      if (!frame.method) { sessionId = frame.sessionId; nonce = frame.nonce; respond(frame, status('LISTENING')); done(); return; }
      if (frame.sessionId !== sessionId || frame.nonce !== nonce) throw Error('ISOLATED_PEER_STALE_SESSION');
      let result: unknown;
      switch (frame.method) {
        case 'accept': break;
        case 'loaded': peer.observation.state = 'LOADED'; peer.observation.loadedNonce = digest('phase-zero');
          peer.observation.nativeWithoutMain = 'DENIED'; break;
        case 'ci-prepare': peer.observation.state = 'RUNNING'; peer.observation.activeOperations = 1; break;
        case 'ci-poll': {
          const effect = peer.observation.ciEffect;
          if (!effect || (effect.state === 'ACKNOWLEDGED' && effect.sequence < runnerEffects.length)) requestNextEffect();
          else if (effect.state === 'ADMITTED') {
            const outcome = { schema: 'publication-ci-effect-outcome/v1' as const, effectId: effect.effectId,
              descriptorSha256: effect.descriptorSha256, admissionId: effect.admissionId!, state: 'SUCCEEDED' as const,
              result: { isolatedEffect: effect.descriptor.kind } };
            Object.assign(effect, { state: 'SUCCEEDED', outcome, outcomeSha256: digest(outcome) });
          } else if (effect.state === 'ACKNOWLEDGED') { peer.observation.state = 'FINISHED'; peer.observation.activeOperations = 0; }
          break;
        }
        case 'effect-admit': Object.assign(peer.observation.ciEffect!, { state: 'ADMITTED', admissionId: frame.args.admissionId }); break;
        case 'effect-ack': peer.observation.ciEffect!.state = 'ACKNOWLEDGED'; break;
        case 'observe-park': result = status('PARKED'); break;
        case 'observe-wait': wake = () => { wake = undefined; respond(frame, peer); }; markWaiting(); done(); return;
        case 'observe-resume': sessionId = frame.args.sessionId; resumed = true;
          if (peer.observation.state !== 'RETIRED') peer.observation.loadedNonce = digest('phase-one');
          result = status('LISTENING'); break;
        case 'current':
          if (resumed && peer.observation.ciEffect?.descriptor.kind === 'jit-register-start') requestNextEffect();
          if (probeBytes) peer.observation.probe = { boundedWirePayload: 'x'.repeat(probeBytes) };
          break;
        case 'fence': peer.observation.state = 'FENCED'; peer.observation.fenceRevision++; break;
        case 'drain': peer.observation.state = 'DRAINED'; break;
        case 'retire': peer.observation.state = 'RETIRED'; break;
        default: throw Error('ISOLATED_PEER_METHOD');
      }
      respond(frame, result ?? peer); done();
    } catch (error) { done(error as Error); }
  } });
  Object.assign(child, { pid: 12345, stdio: Array.from({ length: 15 }, (_, i) => i === 13 ? commands : i === 14 ? responses : null),
    kill: () => { responses.end(); child.emit('close', 0); return true; } });
  processBoundary.spawn.mockReturnValueOnce(child);
  const source = await f.start(); cleanup.push(() => source.revoke());
  const handle = await source.acceptOriginal();
  return { ...f, source, handle, frames, peer, responseBytes: () => responseBytes,
    wake: () => { if (!wake) throw Error('OBSERVATION_WAKE_NOT_AWAITED'); wake(); },
    partialWake: () => { if (!wake) throw Error('OBSERVATION_WAKE_NOT_AWAITED'); partialResponse = true; wake(); },
    extraFragment: () => responses.write(Buffer.from(' ')),
    waitStarted, waiting: () => wake !== undefined, eof: () => responses.end(), setProbeBytes: (n: number) => { probeBytes = n; } };
}

it('ends a current session before a long effect-free wait and refreshes only the held original peer once', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  let elapsed = 0; vi.spyOn(performance, 'now').mockImplementation(() => elapsed);
  const f = await heldFixture(), before = readOriginalPublicationPeerReceipt(f.handle, f.source);
  const park = await f.source.parkForObservation();
  expect(() => readOriginalPublicationPeerReceipt(f.handle, f.source)).toThrow('CLOSED');
  await expect(f.source.current(f.handle)).rejects.toThrow('CLOSED');
  await f.source.waitForObservation(park);
  const quiet = f.frames.length;
  elapsed += 180000; await vi.advanceTimersByTimeAsync(180000);
  expect(f.frames).toHaveLength(quiet);
  const resumed = (await f.source.resumeAfterObservation(park)).get(before.instanceId)!;
  const after = readOriginalPublicationPeerReceipt(resumed, f.source);
  expect(after.process).toEqual(before.process);
  expect(after.observation.state).toBe('LOADED');
  expect(after.observation.loadedNonce).not.toBe(before.observation.loadedNonce);
  expect(f.source.continuityEpoch()).toBe(1);
  expect(() => readOriginalPublicationPeerReceipt(f.handle, f.source)).toThrow('STALE_PEER_RECEIPT');
  const resume = f.frames.find(x => x.method === 'observe-resume')!;
  expect(resume.args.sessionId).not.toBe(f.frames[0].sessionId);
  expect(resume.args.expiresAt - Date.now()).toBeLessThanOrEqual(60000);
  expect(f.frames.at(-1)!.sessionId).toBe(resume.args.sessionId);
  await expect(f.source.resumeAfterObservation(park)).rejects.toThrow('OBSERVATION_CLOSED');
  await expect(f.source.parkForObservation()).rejects.toThrow('OBSERVATION_PHASE');
});

it('persists start completion before a private checkpoint, waits without effects, then gates cleanup in the fresh session', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  let elapsed = 0; vi.spyOn(performance, 'now').mockImplementation(() => elapsed);
  const f = await heldFixture(true), approve = vi.fn();
  const producer = RestrictedPublicationCIProducer.fromOriginal(f.store, 'plugin', f.source, f.handle,
    { instanceId: f.profile.owners[0].instanceId, effects: runnerEffects, assertEffectApproved: approve });
  const advanced = await producer.advanceUntilPark();
  if (advanced.state !== 'PARK_READY') throw Error('MISSING_ORIGINAL_CHECKPOINT');
  const effects = () => f.rows().map(row => JSON.parse((row as { payload: string }).payload))
    .filter(row => row.schema === 'publication-ci-runner-effect/v1');
  expect(effects().map(row => [row.descriptor.kind, row.state]).sort()).toEqual([
    ['jit-prepare', 'COMPLETE'], ['jit-register-start', 'COMPLETE']]);
  expect(approve).toHaveBeenCalledTimes(2);
  const parked = await f.source.parkForObservation([advanced.checkpoint]);
  expect(await f.store.unresolvedConsumerGuardAdmissions('plugin', f.expected.accountId)).toBe(1);
  const wait = f.source.waitForObservation(parked); await f.waitStarted;
  const quiet = f.frames.length;
  elapsed += 180000; await vi.advanceTimersByTimeAsync(180000);
  expect(f.frames).toHaveLength(quiet);
  expect(approve).toHaveBeenCalledTimes(2);
  expect(f.peer.observation.activeOperations).toBe(1);
  await expect(f.source.transition(advanced.handle, 'drain')).rejects.toThrow('CLOSED');
  f.wake(); await wait;
  const map = await f.source.resumeAfterObservation(parked), fresh = map.get(f.profile.owners[0].instanceId)!;
  expect(readOriginalPublicationPeerReceipt(fresh, f.source).observation.ciEffect?.state).toBe('REQUESTED');
  expect(approve).toHaveBeenCalledTimes(2);
  let finished = await producer.finishAfterObservation(advanced.checkpoint, fresh);
  expect(readOriginalPublicationPeerReceipt(finished, f.source).observation.activeOperations).toBe(0);
  expect(approve).toHaveBeenCalledTimes(3);
  expect(effects()).toHaveLength(3);
  expect(effects().every(row => row.state === 'COMPLETE')).toBe(true);
  for (const method of ['fence', 'drain', 'retire'] as const) finished = await f.source.transition(finished, method);
  expect(readOriginalPublicationPeerReceipt(finished, f.source).observation.state).toBe('RETIRED');
  expect(f.frames.filter(x => x.method === 'observe-wait')).toHaveLength(1);
  await expect(producer.finishAfterObservation(advanced.checkpoint, fresh)).rejects.toThrow('PRIVATE_OBSERVATION_CHECKPOINT_REQUIRED');
  await expect(producer.advanceUntilPark()).rejects.toThrow('OPERATION_CONSUMED');
});

it.each(['EOF', 'OWNER_CHANGED', 'DURABLE_UNKNOWN'])(
  'a parked %s cannot create a successor session or erase the unresolved disposition', async failure => {
    const f = await heldFixture(), park = await f.source.parkForObservation();
    await f.source.waitForObservation(park);
    const before = f.frames.length;
    if (failure === 'EOF') { f.eof(); await new Promise<void>(resolve => queueMicrotask(resolve)); }
    else if (failure === 'OWNER_CHANGED') f.expected.ownerEpoch++;
    else {
      const key = digest(['publication-original-owner-listener/v1', f.expected.deviceId, 'original-operation', f.profile.runtimeDirectory]);
      const row = (await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key))!;
      await f.store.compareAndSwapConsumerGuardReceipt('plugin', f.expected.accountId, key, row,
        canonical({ ...JSON.parse(row.payload), state: 'PARKING_UNKNOWN' }));
    }
    await expect(f.source.resumeAfterObservation(park)).rejects.toThrow();
    expect(f.frames).toHaveLength(before);
    await f.source.revoke();
    expect(await f.store.unresolvedConsumerGuardAdmissions('plugin', f.expected.accountId)).toBe(1);
    const states = f.rows().map(row => JSON.parse((row as { payload: string }).payload))
      .filter(row => row.schema === 'publication-original-owner-listener/v1').map(row => row.state);
    expect(states).toEqual(['PARKING_UNKNOWN']);
  });

it.each(['before-park', 'after-wake'])(
  'the original start COMPLETE becoming UNKNOWN %s forbids phase continuation', async when => {
    const f = await heldFixture(true);
    const producer = RestrictedPublicationCIProducer.fromOriginal(f.store, 'plugin', f.source, f.handle,
      { instanceId: f.profile.owners[0].instanceId, effects: runnerEffects, assertEffectApproved: () => {} });
    const advanced = await producer.advanceUntilPark();
    if (advanced.state !== 'PARK_READY') throw Error('MISSING_ORIGINAL_CHECKPOINT');
    let park: object | undefined;
    if (when === 'after-wake') {
      park = await f.source.parkForObservation([advanced.checkpoint]);
      const wait = f.source.waitForObservation(park); await f.waitStarted; f.wake(); await wait;
    }
    const key = digest(['publication-ci-runner-effect/v1', originalCIEffectTarget(runnerEffects[1])]);
    const row = (await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key))!;
    expect(await f.store.compareAndSwapConsumerGuardReceipt('plugin', f.expected.accountId, key, row,
      canonical({ ...JSON.parse(row.payload), state: 'UNKNOWN' }))).toBe(true);
    const before = f.frames.length;
    await expect(park ? f.source.resumeAfterObservation(park) : f.source.parkForObservation([advanced.checkpoint]))
      .rejects.toThrow('OBSERVATION_DISPOSITION_CHANGED');
    expect(f.frames).toHaveLength(before);
    expect(JSON.parse((await f.store.readConsumerGuardReceipt('plugin', f.expected.accountId, key))!.payload).state).toBe('UNKNOWN');
    expect(f.frames.filter(frame => frame.method === 'effect-admit')).toHaveLength(2);
  });

it('allows a long quiet observation but bounds a partial wake frame from its first byte without refresh', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  const f = await heldFixture(true);
  const producer = RestrictedPublicationCIProducer.fromOriginal(f.store, 'plugin', f.source, f.handle,
    { instanceId: f.profile.owners[0].instanceId, effects: runnerEffects, assertEffectApproved: () => {} });
  const advanced = await producer.advanceUntilPark();
  if (advanced.state !== 'PARK_READY') throw Error('MISSING_ORIGINAL_CHECKPOINT');
  const park = await f.source.parkForObservation([advanced.checkpoint]);
  const wait = f.source.waitForObservation(park), refused = expect(wait).rejects.toThrow('TIMEOUT');
  await f.waitStarted;
  await vi.advanceTimersByTimeAsync(180000);
  expect(f.source.diagnostics().closed).toBe(false);
  f.partialWake(); await vi.advanceTimersByTimeAsync(2000);
  f.extraFragment(); await vi.advanceTimersByTimeAsync(999);
  expect(f.source.diagnostics().closed).toBe(false);
  await vi.advanceTimersByTimeAsync(1); await refused;
  expect(f.source.diagnostics().closed).toBe(true);
  await expect(f.source.resumeAfterObservation(park)).rejects.toThrow('OBSERVATION_CLOSED');
  expect(f.frames.filter(frame => frame.method === 'observe-resume')).toEqual([]);
});

it('retains only terminal evidence for an already retired peer without fabricating a new live loaded nonce', async () => {
  const f = await heldFixture(); let retired = f.handle;
  for (const method of ['fence', 'drain', 'retire'] as const) retired = await f.source.transition(retired, method);
  const before = readOriginalPublicationPeerReceipt(retired, f.source);
  const park = await f.source.parkForObservation(); await f.source.waitForObservation(park);
  const fresh = (await f.source.resumeAfterObservation(park)).get(before.instanceId)!;
  expect(readOriginalPublicationPeerReceipt(fresh, f.source)).toEqual(before);
  expect(() => readOriginalPublicationPeerReceipt(retired, f.source)).toThrow('STALE_PEER_RECEIPT');
  const count = f.frames.length;
  await expect(f.source.transition(fresh, 'fence')).rejects.toThrow('PHASE');
  expect(f.frames).toHaveLength(count);
});

it('an expired first session cannot be parked into a replacement deadline', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  let elapsed = 0; vi.spyOn(performance, 'now').mockImplementation(() => elapsed);
  const f = await heldFixture(); elapsed = 60001;
  await vi.advanceTimersByTimeAsync(60001);
  const before = f.frames.length;
  await expect(f.source.parkForObservation()).rejects.toThrow('CLOSED');
  expect(f.frames).toHaveLength(before);
  expect(f.source.diagnostics().closed).toBe(true);
});

it.each(['messages', 'bytes'])('retains the cumulative %s budget across the observation interval', async budget => {
  const f = await heldFixture();
  if (budget === 'bytes') f.setProbeBytes(45000);
  for (let i = 0; i < (budget === 'messages' ? 50 : 12); i++) await f.source.current(f.handle);
  const park = await f.source.parkForObservation(); await f.source.waitForObservation(park);
  const fresh = (await f.source.resumeAfterObservation(park)).get(f.profile.owners[0].instanceId)!;
  let failure: unknown;
  for (let i = 0; i < (budget === 'messages' ? 80 : 20); i++) {
    try { await f.source.current(fresh); } catch (error) { failure = error; break; }
  }
  expect(String(failure)).toContain(budget === 'messages' ? 'SEQUENCE' : 'FRAME_INVALID');
  if (budget === 'messages') expect(f.frames.at(-1)!.seq).toBe(128);
  else expect(f.responseBytes()).toBeGreaterThan(1048576);
  expect(f.source.diagnostics().closed).toBe(true);
});

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

it.each(['PARKING_UNKNOWN', 'OBSERVING', 'RESUMING_UNKNOWN'])(
  'a replacement Main cannot reconstruct the original observation continuation from %s JSON', async state => {
    const f = await fixture(), key = digest(['original-observation-history', state]);
    expect(await f.store.compareAndSwapConsumerGuardReceipt('plugin', f.expected.accountId, key, undefined,
      canonical({ schema: 'publication-original-owner-listener/v1', runtimeDirectory: f.profile.runtimeDirectory, state }))).toBe(true);
    const before = f.rows();
    await expect(f.start('replacement-main-operation')).rejects.toThrow('PRIOR_POLICY_CUTOVER_UNKNOWN');
    expect(f.rows()).toEqual(before);
    expect(processBoundary.spawn).not.toHaveBeenCalled();
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
    pending: { seq: 1, terminal, sessionId: digest('session'), timer, resolve: (value: unknown) => { resolved = value; } },
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
