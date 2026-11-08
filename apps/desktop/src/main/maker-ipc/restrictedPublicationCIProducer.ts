/** Main's per-effect admission for a kernel-authenticated original CI runner.
 * This owns runner effects only. It cannot establish workflow history, approve
 * an installation, or turn a caller-supplied observation into source authority.
 */
import { randomBytes } from 'node:crypto';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import { canonical, digest } from './restrictedPublicationProtocol.js';
import {
  isOriginalPublicationSource, readOriginalPublicationPeerReceipt,
  type OriginalPublicationPeerObservation, type RestrictedPublicationResidentSource,
} from './restrictedPublicationResidentSource.js';

export const originalCIEffectKinds = ['persistent-registration', 'persistent-configure',
  'persistent-retire', 'jit-prepare', 'jit-register-start', 'jit-cleanup', 'controller-start'] as const;
export interface OriginalCIEffectDescriptor {
  schema: 'publication-ci-effect/v1';
  kind: (typeof originalCIEffectKinds)[number];
  identity: Record<string, unknown>;
}
export interface OriginalCIEffectOutcome {
  schema: 'publication-ci-effect-outcome/v1'; effectId: string; descriptorSha256: string;
  admissionId: string; state: 'SUCCEEDED' | 'UNKNOWN'; result: Record<string, unknown> | null;
}
export interface OriginalCIEffectObservation {
  sequence: number; effectId: string; descriptorSha256: string; descriptor: OriginalCIEffectDescriptor;
  state: 'REQUESTED' | 'ADMITTED' | 'RUNNING' | 'SUCCEEDED' | 'ACKNOWLEDGED' | 'UNKNOWN';
  admissionId: string | null; outcome: OriginalCIEffectOutcome | null; outcomeSha256: string | null;
}
export interface OriginalCIRunnerPlan {
  instanceId: string;
  /** Fixed Main targets. Only persistent-retire may omit unitInvocationId until
   * the original producer observes it; every other field remains exact. */
  effects: readonly OriginalCIEffectDescriptor[];
  /** Receives the complete actually observed descriptor before durable admit.
   * This callback is original Main authority, never supplied over IPC. */
  assertEffectApproved(effect: Readonly<OriginalCIEffectDescriptor>): void | Promise<void>;
}
type Store = Pick<ReturnType<typeof createRestrictedPartnerStore>,
  'readConsumerGuardReceipt' | 'compareAndSwapConsumerGuardReceipt' |
  'unresolvedConsumerGuardAdmissions' | 'unknownNativePublicationEffects'>;
type Row = NonNullable<Awaited<ReturnType<Store['readConsumerGuardReceipt']>>>;
type EffectRecord = {
  schema: 'publication-ci-runner-effect/v1'; scope: 'REGISTERED_CI_PRODUCER';
  operationId: string; binding: ReturnType<RestrictedPublicationResidentSource['binding']>;
  instanceId: string; ownerId: string; peerId: string; processIdentity: string;
  sourceDigest: string; definitionDigest: string; sequence: number;
  effectId: string; descriptorSha256: string; descriptor: OriginalCIEffectDescriptor; admissionId: string;
  targetSha256: string;
  state: 'DISPATCHING_UNKNOWN' | 'APPLIED_UNACKNOWLEDGED' | 'COMPLETE' | 'UNKNOWN';
  outcome: OriginalCIEffectOutcome | null; outcomeSha256: string | null;
};
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
function fail(code: string): never { throw Error('PUBLICATION_CI_PRODUCER_' + code); }
function exact(value: unknown, keys: string): asserts value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== keys.split(',').sort().join(',')) fail('SCHEMA');
}
/** Stable effect identity excludes Main generation, boot and operation.
 * The original producer supplies its fixed target identity; Main matches its
 * complete descriptor (including a workflow attempt where applicable) to the
 * approved plan. A prior UNKNOWN also blocks the original account-wide gate. */
export function originalCIEffectIdentity(value: unknown) {
  exact(value, 'schema,kind,identity');
  if (value.schema !== 'publication-ci-effect/v1' || !originalCIEffectKinds.includes(value.kind) ||
      !value.identity || typeof value.identity !== 'object' || Array.isArray(value.identity) ||
      !Object.keys(value.identity).length || Buffer.byteLength(canonical(value)) > 8192) fail('DESCRIPTOR');
  return digest(value);
}
const jitIdentityKeys = 'repository,route,runId,attempt,jobId,headSha,workflowPath,workflowBlob,goldenSha256';
const effectIdentityKeys: Readonly<Record<OriginalCIEffectDescriptor['kind'], string>> = {
  'persistent-registration': 'repository,poolId,poolDigest,runnerNames,distro',
  'persistent-configure': 'repository,poolId,poolDigest,runnerNames,units,runnerDirectories,distro',
  'persistent-retire': 'repository,poolId,poolDigest,runnerName,runnerId,unit,unitInvocationId,distro',
  'jit-prepare': jitIdentityKeys, 'jit-register-start': jitIdentityKeys, 'jit-cleanup': jitIdentityKeys,
  'controller-start': 'repository,route,runId,controllerSha256',
};
/** Validate expectation metadata, never an observed receipt or admission. The
 * sole late observation is the retiring unit's actual invocation identity. */
export function originalCIEffectPlanIdentity(value: OriginalCIEffectDescriptor) {
  const id = originalCIEffectIdentity(value);
  const late = value.kind === 'persistent-retire' && !Object.hasOwn(value.identity, 'unitInvocationId');
  exact(value.identity, effectIdentityKeys[value.kind].split(',')
    .filter(key => !late || key !== 'unitInvocationId').join(','));
  if (Object.values(value.identity).some(item => item === null || item === undefined) ||
      (value.kind === 'persistent-retire' && !late &&
        (typeof value.identity.unitInvocationId !== 'string' || !/^[a-f0-9]{32}$/.test(value.identity.unitInvocationId))))
    fail('PLAN');
  originalCIEffectTarget(value);
  return id;
}
/** Exact comparison against a fixed Main expectation. A true return is still
 * only metadata comparison; the caller must hold the original private source. */
export function matchesOriginalCIEffectPlan(expected: OriginalCIEffectDescriptor, observed: OriginalCIEffectDescriptor) {
  originalCIEffectPlanIdentity(expected);
  originalCIEffectIdentity(observed);
  exact(observed.identity, effectIdentityKeys[observed.kind]);
  if (observed.kind === 'persistent-retire' &&
      (typeof observed.identity.unitInvocationId !== 'string' || !/^[a-f0-9]{32}$/.test(observed.identity.unitInvocationId)))
    fail('EFFECT');
  if (expected.kind === 'persistent-retire' && observed.kind === expected.kind &&
      !Object.hasOwn(expected.identity, 'unitInvocationId')) {
    const identity = { ...observed.identity }; delete identity.unitInvocationId;
    return canonical(expected) === canonical({ ...observed, identity });
  }
  return canonical(expected) === canonical(observed);
}
/** Semantic target identity also excludes reviewed source/config hashes. A
 * changed controller, pool digest or workflow blob must not make the same
 * original operation retryable. Main still approves the full descriptor. */
export function originalCIEffectTarget(descriptor: OriginalCIEffectDescriptor) {
  originalCIEffectIdentity(descriptor);
  const fields: Readonly<Record<OriginalCIEffectDescriptor['kind'], readonly string[]>> = {
    'persistent-registration': ['repository', 'poolId', 'distro', 'runnerNames'],
    'persistent-configure': ['repository', 'poolId', 'distro', 'runnerNames'],
    'persistent-retire': ['repository', 'poolId', 'distro', 'runnerId'],
    'jit-prepare': ['repository', 'route', 'runId', 'attempt', 'jobId'],
    'jit-register-start': ['repository', 'route', 'runId', 'attempt', 'jobId'],
    'jit-cleanup': ['repository', 'route', 'runId', 'attempt', 'jobId'],
    'controller-start': ['repository', 'route', 'runId'],
  };
  const identity: Record<string, unknown> = {};
  for (const key of fields[descriptor.kind]) {
    const value = descriptor.identity[key];
    if (key === 'runnerNames') {
      if (!Array.isArray(value) || !value.length || value.length > 64 ||
          value.some(x => typeof x !== 'string' || !/^windows-ayc-core-bridge-ci-[0-9]{2,}$/.test(x)) ||
          new Set(value).size !== value.length) fail('TARGET');
      identity[key] = [...value].sort();
    } else if (['runId', 'attempt', 'jobId', 'runnerId'].includes(key)) {
      if (!Number.isSafeInteger(value) || Number(value) < 1) fail('TARGET');
      identity[key] = value;
    } else {
      if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 512 || /[\u0000-\u001f\u007f-\u009f]/.test(value))
        fail('TARGET');
      identity[key] = value;
    }
  }
  return digest({ schema: 'publication-ci-effect-target/v1', kind: descriptor.kind, identity });
}
/** Syntax checks on an authenticated reply. The return value is not authority. */
export function validateOriginalCIEffect(value: unknown): asserts value is OriginalCIEffectObservation | null {
  if (value === null) return;
  exact(value, 'sequence,effectId,descriptorSha256,descriptor,state,admissionId,outcome,outcomeSha256');
  const expected = originalCIEffectIdentity(value.descriptor);
  if (!Number.isSafeInteger(value.sequence) || value.sequence < 1 || value.sequence > 128 ||
      value.effectId !== expected || value.descriptorSha256 !== expected ||
      !['REQUESTED', 'ADMITTED', 'RUNNING', 'SUCCEEDED', 'ACKNOWLEDGED', 'UNKNOWN'].includes(value.state)) fail('EFFECT');
  if (value.state === 'REQUESTED') {
    if (value.admissionId !== null || value.outcome !== null || value.outcomeSha256 !== null) fail('EFFECT');
    return;
  }
  if (!hex(value.admissionId)) fail('ADMISSION');
  if (value.state === 'ADMITTED' || value.state === 'RUNNING') {
    if (value.outcome !== null || value.outcomeSha256 !== null) fail('OUTCOME');
    return;
  }
  exact(value.outcome, 'schema,effectId,descriptorSha256,admissionId,state,result');
  const result = value.outcome.result;
  if (value.outcome.schema !== 'publication-ci-effect-outcome/v1' ||
      value.outcome.effectId !== expected || value.outcome.descriptorSha256 !== expected ||
      value.outcome.admissionId !== value.admissionId ||
      value.outcome.state !== (value.state === 'UNKNOWN' ? 'UNKNOWN' : 'SUCCEEDED') ||
      (result !== null && (!result || typeof result !== 'object' || Array.isArray(result))) ||
      (value.state !== 'UNKNOWN' && result === null) || Buffer.byteLength(canonical(result)) > 8192 ||
      digest(value.outcome) !== value.outcomeSha256) fail('OUTCOME');
}
type Permit = { producer: RestrictedPublicationCIProducer; source: RestrictedPublicationResidentSource;
  kind: 'admit' | 'ack'; row: Row; observation: OriginalPublicationPeerObservation; used: boolean };
const permits = new WeakMap<object, Permit>();
const producers = new WeakSet<object>();
type ObservationCheckpoint = { producer: RestrictedPublicationCIProducer; source: RestrictedPublicationResidentSource;
  key: string; row: Row; value: EffectRecord; observation: OriginalPublicationPeerObservation;
  epoch: number; parked: boolean; consumed: boolean };
const observationCheckpoints = new WeakMap<object, ObservationCheckpoint>();
export type OriginalCIProducerAdvance = { state: 'FINISHED'; handle: object } |
  { state: 'PARK_READY'; handle: object; checkpoint: object };
/** This is a Main-held continuation of an already completed start effect, not
 * an effect permit. JSON, a durable row, or a replacement producer cannot mint
 * it. The original source consumes it before ending its first short session. */
export async function consumeOriginalCIObservationCheckpoint(handle: object,
  source: RestrictedPublicationResidentSource) {
  const checkpoint = observationCheckpoints.get(handle);
  if (!checkpoint || checkpoint.source !== source || checkpoint.parked || checkpoint.consumed ||
      !producers.has(checkpoint.producer)) fail('PRIVATE_OBSERVATION_CHECKPOINT_REQUIRED');
  checkpoint.parked = true;
  await checkpoint.producer.verifyObservationCheckpoint(checkpoint, true);
  return structuredClone(checkpoint.observation);
}
/** Recheck the exact durable winner while no live effect session exists. This
 * never reads an old peer receipt as current or recreates a continuation. */
export async function verifyOriginalCIObservationCheckpoint(handle: object,
  source: RestrictedPublicationResidentSource) {
  const checkpoint = observationCheckpoints.get(handle);
  if (!checkpoint || checkpoint.source !== source || !checkpoint.parked || checkpoint.consumed ||
      !producers.has(checkpoint.producer)) fail('PRIVATE_OBSERVATION_CHECKPOINT_REQUIRED');
  await checkpoint.producer.verifyObservationCheckpoint(checkpoint, false);
}
/** Called only by the original listener adapter, immediately before its wire
 * write. Durable state is rechecked and the capability is consumed once. */
export async function consumeOriginalCIEffectPermit(handle: object, source: RestrictedPublicationResidentSource,
  observation: OriginalPublicationPeerObservation, kind: 'admit' | 'ack') {
  const p = permits.get(handle);
  if (!p || p.used || p.source !== source || p.kind !== kind || !producers.has(p.producer) ||
      canonical(p.observation) !== canonical(observation)) fail('PRIVATE_PERMIT_REQUIRED');
  // Claim synchronously before the first await, including unsuccessful reads.
  // Two callers must never both pass a one-use permit's availability check.
  p.used = true;
  await p.producer.verifyPermit(p.row, observation, kind);
  const value = JSON.parse(p.row.payload) as EffectRecord;
  return { effectId: value.effectId, descriptorSha256: value.descriptorSha256, admissionId: value.admissionId,
    ...(kind === 'ack' ? { outcomeSha256: value.outcomeSha256! } : {}) };
}

export class RestrictedPublicationCIProducer {
  private readonly approved: ReadonlyMap<string, OriginalCIEffectDescriptor>;
  private readonly approve: OriginalCIRunnerPlan['assertEffectApproved'];
  private handle: object;
  private current?: { key: string; row: Row; value: EffectRecord };
  private readonly completed = new Set<string>();
  private running = false;
  private used = false;
  private checkpoint?: object;
  private constructor(private readonly store: Store, private readonly plugin: string,
    private readonly source: RestrictedPublicationResidentSource, handle: object, plan: OriginalCIRunnerPlan) {
    if (!isOriginalPublicationSource(source)) fail('ORIGINAL_SOURCE_REQUIRED');
    const observed = readOriginalPublicationPeerReceipt(handle, source);
    if (observed.sourceScope !== 'REGISTERED_CI_PRODUCER' || observed.instanceId !== plan.instanceId ||
        observed.observation.state !== 'LOADED' || observed.observation.activeOperations !== 0 ||
        observed.observation.unknownOperations !== 0 || observed.observation.ciEffect !== null ||
        typeof plan.assertEffectApproved !== 'function' || !Array.isArray(plan.effects) ||
        !plan.effects.length || plan.effects.length > 64) fail('PLAN');
    const expected = plan.effects.map(x => {
      originalCIEffectPlanIdentity(x);
      return [originalCIEffectTarget(x), structuredClone(x)] as const;
    });
    if (new Set(expected.map(x => x[0])).size !== expected.length) fail('PLAN');
    this.approved = new Map(expected); this.approve = plan.assertEffectApproved;
    this.handle = handle; producers.add(this);
  }
  static fromOriginal(store: Store, plugin: string, source: RestrictedPublicationResidentSource,
    handle: object, plan: OriginalCIRunnerPlan) {
    return new RestrictedPublicationCIProducer(store, plugin, source, handle, plan);
  }
  private observation() {
    const value = readOriginalPublicationPeerReceipt(this.handle, this.source);
    if (value.sourceScope !== 'REGISTERED_CI_PRODUCER') fail('ORIGINAL_SOURCE_REQUIRED');
    validateOriginalCIEffect(value.observation.ciEffect);
    return value;
  }
  private async save(value: EffectRecord) {
    const current = this.current;
    if (!current || !await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, value.binding.accountId,
      current.key, current.row, canonical(value))) fail('LEDGER_CHANGED');
    const row = { revision: current.row.revision + 1, payload: canonical(value) };
    const actual = await this.store.readConsumerGuardReceipt(this.plugin, value.binding.accountId, current.key);
    if (canonical(actual) !== canonical(row)) fail('LEDGER_CHANGED');
    this.current = { key: current.key, row, value };
  }
  async verifyPermit(row: Row, observation: OriginalPublicationPeerObservation, kind: 'admit' | 'ack') {
    const current = this.current;
    this.source.binding();
    if (!this.running || !current || canonical(current.row) !== canonical(row) ||
        canonical(await this.store.readConsumerGuardReceipt(this.plugin, current.value.binding.accountId,
          current.key)) !== canonical(row) || canonical(this.observation()) !== canonical(observation) ||
        current.value.state !== (kind === 'admit' ? 'DISPATCHING_UNKNOWN' : 'APPLIED_UNACKNOWLEDGED'))
      fail('LEDGER_CHANGED');
    this.source.binding();
  }
  private permit(kind: 'admit' | 'ack') {
    const handle = Object.freeze(Object.create(null)) as object;
    permits.set(handle, { producer: this, source: this.source, kind,
      row: structuredClone(this.current!.row), observation: this.observation(), used: false });
    return handle;
  }
  private async claim(observed: OriginalPublicationPeerObservation, effect: OriginalCIEffectObservation) {
    const targetSha256 = originalCIEffectTarget(effect.descriptor);
    const expected = this.approved.get(targetSha256);
    if (effect.state !== 'REQUESTED' || !expected || !matchesOriginalCIEffectPlan(expected, effect.descriptor) ||
        this.completed.has(effect.effectId)) fail('EFFECT_NOT_APPROVED');
    const binding = this.source.binding();
    const assertDrained = async () => {
      if (await this.store.unresolvedConsumerGuardAdmissions(this.plugin, binding.accountId) !== 0 ||
          await this.store.unknownNativePublicationEffects(this.plugin) !== 0) fail('PRIOR_EFFECT_UNRESOLVED');
    };
    // No operation/boot/generation/device component: replacing any of those
    // cannot replay an already claimed target in this original account DB.
    const key = digest(['publication-ci-runner-effect/v1', targetSha256]);
    if (await this.store.readConsumerGuardReceipt(this.plugin, binding.accountId, key)) fail('EFFECT_ALREADY_CLAIMED');
    await assertDrained();
    await this.approve(structuredClone(effect.descriptor));
    await assertDrained();
    if (canonical(this.source.binding()) !== canonical(binding) || canonical(this.observation()) !== canonical(observed))
      fail('SOURCE_CHANGED');
    const value: EffectRecord = { schema: 'publication-ci-runner-effect/v1', scope: 'REGISTERED_CI_PRODUCER',
      operationId: this.source.operationId, binding, instanceId: observed.instanceId, ownerId: observed.ownerId,
      peerId: observed.peerId, processIdentity: digest(observed.process), sourceDigest: observed.sourceDigest,
      definitionDigest: observed.definitionDigest, sequence: effect.sequence, effectId: effect.effectId,
      descriptorSha256: effect.descriptorSha256, descriptor: structuredClone(effect.descriptor), targetSha256,
      admissionId: randomBytes(32).toString('hex'), state: 'DISPATCHING_UNKNOWN', outcome: null, outcomeSha256: null };
    if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, binding.accountId, key, undefined, canonical(value)))
      fail('EFFECT_ALREADY_CLAIMED');
    const row = { revision: 1, payload: canonical(value) };
    if (canonical(await this.store.readConsumerGuardReceipt(this.plugin, binding.accountId, key)) !== canonical(row))
      fail('LEDGER_CHANGED');
    this.current = { key, row, value };
  }
  async verifyObservationCheckpoint(checkpoint: ObservationCheckpoint, requireCurrent: boolean) {
    if (!this.checkpoint || observationCheckpoints.get(this.checkpoint) !== checkpoint ||
        checkpoint.producer !== this || checkpoint.source !== this.source || this.running || this.current ||
        checkpoint.value.state !== 'COMPLETE' || checkpoint.value.descriptor.kind !== 'jit-register-start' ||
        canonical(await this.store.readConsumerGuardReceipt(this.plugin, checkpoint.value.binding.accountId,
          checkpoint.key)) !== canonical(checkpoint.row)) fail('OBSERVATION_DISPOSITION_CHANGED');
    if (requireCurrent && (this.source.continuityEpoch() !== checkpoint.epoch ||
        canonical(this.observation()) !== canonical(checkpoint.observation))) fail('SOURCE_CHANGED');
  }
  private async advance(stopAtObservation: boolean): Promise<OriginalCIProducerAdvance> {
    for (;;) {
      const observed = this.observation();
      const effect = observed.observation.ciEffect;
      if (observed.observation.unknownOperations !== 0 || observed.observation.state === 'UNKNOWN' ||
          effect?.state === 'UNKNOWN') fail('OUTCOME_UNKNOWN');
      if (observed.observation.state === 'FINISHED') {
        if (observed.observation.activeOperations !== 0 ||
            (effect !== null && effect?.state !== 'ACKNOWLEDGED') || this.current) fail('OUTCOME_UNKNOWN');
        return { state: 'FINISHED', handle: this.handle };
      }
      if (observed.observation.state !== 'RUNNING') fail('PHASE');
      if (!effect || effect.state === 'ACKNOWLEDGED') {
        this.handle = await this.source.pollCI(this.handle); continue;
      }
      await this.claim(observed, effect);
      this.handle = await this.source.admitCIEffect(this.handle, this.permit('admit'));
      let outcome = this.observation().observation.ciEffect;
      while (outcome?.state === 'ADMITTED' || outcome?.state === 'RUNNING') {
        this.handle = await this.source.pollCI(this.handle);
        outcome = this.observation().observation.ciEffect;
      }
      if (!outcome || outcome.state !== 'SUCCEEDED' || !outcome.outcome || !this.current ||
          outcome.effectId !== this.current.value.effectId || outcome.admissionId !== this.current.value.admissionId)
        fail('OUTCOME_UNKNOWN');
      await this.save({ ...this.current.value, state: 'APPLIED_UNACKNOWLEDGED',
        outcome: structuredClone(outcome.outcome), outcomeSha256: outcome.outcomeSha256 });
      this.handle = await this.source.acknowledgeCIEffect(this.handle, this.permit('ack'));
      const ack = this.observation().observation.ciEffect;
      if (!ack || ack.state !== 'ACKNOWLEDGED' || ack.outcomeSha256 !== this.current!.value.outcomeSha256)
        fail('ACK_UNKNOWN');
      await this.save({ ...this.current!.value, state: 'COMPLETE' });
      this.completed.add(effect.effectId);
      const completed = this.current!;
      this.current = undefined;
      if (stopAtObservation && effect.descriptor.kind === 'jit-register-start') {
        const observation = this.observation();
        if (this.checkpoint || observation.ownerId !== 'core-jit.bridge-jit-controller' ||
            observation.observation.state !== 'RUNNING' || observation.observation.activeOperations !== 1 ||
            observation.observation.unknownOperations !== 0 || observation.observation.ciEffect?.state !== 'ACKNOWLEDGED')
          fail('OBSERVATION_PHASE');
        const checkpoint = this.checkpoint = Object.freeze(Object.create(null)) as object;
        observationCheckpoints.set(checkpoint, { producer: this, source: this.source, ...structuredClone(completed),
          observation, epoch: this.source.continuityEpoch(), parked: false, consumed: false });
        return { state: 'PARK_READY', handle: this.handle, checkpoint };
      }
    }
  }
  private async failed(error: unknown): Promise<never> {
    // Preserve an already observed success if its ACK is uncertain. Both
    // APPLIED_UNACKNOWLEDGED and UNKNOWN remain unresolved in the original DB.
    if (this.current?.value.state === 'DISPATCHING_UNKNOWN') {
      try { await this.save({ ...this.current.value, state: 'UNKNOWN' }); } catch { /* keep original durable claim */ }
    }
    await this.source.revoke().catch(() => undefined);
    throw error;
  }
  private async start(stopAtObservation: boolean) {
    if (this.used || this.running) fail('OPERATION_CONSUMED');
    this.used = true; this.running = true;
    try {
      this.handle = await this.source.prepareCI(this.handle);
      return await this.advance(stopAtObservation);
    } catch (error) { return await this.failed(error); }
    finally { this.running = false; }
  }
  /** Existing single-session entry. Its deadline and total budgets remain
   * unchanged; only the explicit Main coordinator may select the phase plan. */
  async run() { return (await this.start(false)).handle; }
  /** Stop immediately after the exact start effect's durable ACK. Main can
   * dispatch B and park every already authenticated source before any wait. */
  async advanceUntilPark(): Promise<OriginalCIProducerAdvance> { return this.start(true); }
  async finishAfterObservation(handle: object, resumedPeer: object) {
    const checkpoint = observationCheckpoints.get(handle);
    if (!checkpoint || this.checkpoint !== handle || checkpoint.producer !== this ||
        checkpoint.source !== this.source || !checkpoint.parked || checkpoint.consumed || this.running ||
        !this.used || this.source.continuityEpoch() !== checkpoint.epoch + 1) fail('PRIVATE_OBSERVATION_CHECKPOINT_REQUIRED');
    checkpoint.consumed = true;
    try {
      await this.verifyObservationCheckpoint(checkpoint, false);
      const observed = readOriginalPublicationPeerReceipt(resumedPeer, this.source);
      const previous = checkpoint.observation;
      const before = previous.observation.ciEffect!, after = observed.observation.ciEffect;
      const nextCleanup = after?.state === 'REQUESTED' && after.sequence === before.sequence + 1 &&
        after.descriptor.kind === 'jit-cleanup' && canonical(after.descriptor.identity) === canonical(before.descriptor.identity);
      if (observed.peerId !== previous.peerId || observed.instanceId !== previous.instanceId ||
          digest(observed.process) !== digest(previous.process) || observed.sourceDigest !== previous.sourceDigest ||
          observed.definitionDigest !== previous.definitionDigest || observed.observation.state !== 'RUNNING' ||
          observed.observation.activeOperations !== 1 || observed.observation.unknownOperations !== 0 ||
          observed.observation.loadedNonce === previous.observation.loadedNonce ||
          observed.observation.fenceRevision !== previous.observation.fenceRevision ||
          (!nextCleanup && canonical(after) !== canonical(before))) fail('OBSERVATION_SOURCE_CHANGED');
      this.handle = resumedPeer; this.running = true;
      const result = await this.advance(false);
      if (result.state !== 'FINISHED') fail('OBSERVATION_PHASE');
      return result.handle;
    } catch (error) { return await this.failed(error); }
    finally { this.running = false; }
  }
}
