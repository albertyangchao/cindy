import path from 'node:path';
import { digest as canonicalDigest } from './restrictedPublicationProtocol.js';
import type { RegisteredPublicationRoot } from './restrictedPublicationCaller.js';
import type { ConsumerGuardCoverageAuthority } from './restrictedPublicationConsumerGuardAuthority.js';
/** Main-private executable adapter. Profiles are expected definitions, never evidence.
 * Unknown foreign controller/namespace receipts remain unsupported, not absent/zero.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import {
  ManagedPublicationController,
  readManagedEnrollmentReceipt,
  readManagedLifecycleReceipt,
  type ManagedLifecycleObservation,
  type PublisherReleaseSource,
} from './restrictedPublicationManagedController.js';
import {
  RestrictedPublicationCISourceBroker,
  readPublicationSourceReceipt,
  type PinnedPublicationSourceWorker,
} from './restrictedPublicationCISourceBroker.js';
import {
  RestrictedPublicationOwnerSource,
  readHeldPublicationOwnerReceipt,
} from './restrictedPublicationOwnerSource.js';
import {
  RestrictedPublicationResidentSource, readOriginalPublicationPeerReceipt,
  type PinnedPublicationResidentSource,
} from './restrictedPublicationResidentSource.js';
import { RestrictedPublicationOwnerRegistry, readOriginalPublicationRegistrySeal } from './restrictedPublicationOwnerRegistry.js';
import { RestrictedPublicationCIProducer, originalCIEffectPlanIdentity, originalCIEffectTarget,
  type OriginalCIRunnerPlan, type OriginalCIEffectDescriptor } from './restrictedPublicationCIProducer.js';
import { assertNoUncertainPublicationCutover, clonePublicationGenerationPlan, publicationGenerationPlanIdentity,
  preparePublicationGenerationCutover, commitPublicationGenerationCutover,
  type MainPublicationGenerationPlan } from './restrictedPublicationPolicyCutover.js';
import {
  coverageEntries,
  adjacentCoverageEntries,
  type CoverageRegistration,
  type ControlledCoverageDriver,
  type ControlledCoverageReport,
} from './restrictedPublicationConsumerGuardAuthority.js';
const sha = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
const validHash = (x: unknown): x is string => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const opaque = (x: unknown): x is string =>
  typeof x === 'string' &&
  x.length > 0 &&
  Buffer.byteLength(x) <= 512 &&
  !/[\u0000-\u001f\u007f]/.test(x);
function fail(code: string): never {
  throw Error('PUBLICATION_DRIVER_' + code);
}
const coreEntryFiles: Record<string, string[]> = {
  'canonical-producer': ['bridge_core/publish_html.py', 'bridge_core/report_publish_queue.py'],
  'generic-direct': ['scripts/publish_generic_html_direct.py'],
  'worksheet-ci': ['scripts/publish_worksheet_html.py'],
  'worksheet-direct': ['scripts/publish_worksheet_html_direct.py'],
  'tracker-direct': ['scripts/publish_tracker_html_direct.py'],
  'shared-transaction': ['scripts/publish_worksheet_html.py'],
  'native-main-dispatch': [],
};
const commonFiles = [
  'bridge_core/publication_consumer_guards.py',
  'bridge_core/publication_consumer_controller.py',
  'bridge_core/publication_consumer_enrollment.py',
  'bridge_core/native_html_release.py',
];
export function coverageEntryDefinition(
  entryId: string,
  files: Readonly<Record<string, string>>,
): string {
  if (!Object.hasOwn(coreEntryFiles, entryId)) fail('ENTRY');
  const expected: Record<string, string> = {};
  for (const p of [...commonFiles, ...coreEntryFiles[entryId]]) {
    if (!validHash(files[p])) fail('ENTRY_SOURCE');
    expected[p] = files[p];
  }
  return canonicalDigest({ entryId, files: expected });
}
type Store = Pick<
  ReturnType<typeof createRestrictedPartnerStore>,
  | 'consumerGuardReceiptIdentity'
  | 'readConsumerGuardReceipt'
  | 'compareAndSwapConsumerGuardReceipt'
  | 'unresolvedConsumerGuardAdmissions'
  | 'unknownNativePublicationEffects'
> & Partial<Pick<ReturnType<typeof createRestrictedPartnerStore>,
  'capturePublicationOwnerHistory' | 'assertPublicationOwnerHistoryCurrent'>>;
export interface FixedCoverageProfile {
  source: PublisherReleaseSource;
  publisher: {
    artifactRoot: string;
    queueRoot: string;
    dispatchRoot: string;
    publicOrigin: string;
  };
  registration: CoverageRegistration;
  instances: ReadonlyArray<{
    instanceId: string;
    entryId: (typeof coverageEntries)[number];
    origin: 'owned-release' | 'foreign-controller';
    state: 'GUARDED' | 'NATIVE_NAMESPACE_DENIED' | 'RETIRED_FENCED';
  }>;
  /** Real original-owner source adapters must supply opaque receipts, not JSON reports.
   * No such foreign producer is registered by this module. */
  foreignSources?: ReadonlyArray<object>;
  namespaceOwnership: Readonly<
    Record<(typeof adjacentCoverageEntries)[number], 'owned-launcher' | 'foreign-controller'>
  >;
}
/** Expected Main deployment configuration only. The callback is the original
 * dispatch approval, never a source/fact provider. No IPC accepts this object. */
export interface MainPublicationSourcePlan {
  operationId: string;
  worker: PinnedPublicationSourceWorker;
  /** Main-approved future expectations; every generation still needs actual original peers. */
  generations?: ReadonlyArray<MainPublicationGenerationPlan>;
  /** An additional held source process; never a substitute for C's original owners. */
  ownerSource?: { instanceId: string; profileId: 'canonical-producer' | 'core.monitor.publish'; definitionDigest: string };
  /** Fixed original-entry listeners. Descriptors remain expectations until the
   * kernel-authenticated original processes connect; this never starts a service. */
  originalSources?: ReadonlyArray<PinnedPublicationResidentSource>;
  /** Additional original runner owners. Their effects retain separate original
   * Main approvals and never substitute for complete CI workflow history. */
  ciRunners?: ReadonlyArray<OriginalCIRunnerPlan>;
  ci?: {
    instanceId: string;
    head: string;
    workflowSha256: string;
    assertDispatchApproved(): void;
  };
}
type SourcePlanMetadata = {
  operationId: string;
  worker: PinnedPublicationSourceWorker;
  ownerSource?: MainPublicationSourcePlan['ownerSource'];
  originalSources?: MainPublicationSourcePlan['originalSources'];
  ciRunners?: Array<Pick<OriginalCIRunnerPlan, 'instanceId' | 'effects'>>;
  ci?: { instanceId: string; head: string; workflowSha256: string };
};
type DriverState = {
  schema: 'publication-coverage-driver/v1';
  boot: string;
  account: string;
  profile: string;
  releaseSequence: number;
  lifecycleSequence: number;
  usedGenerations: string[];
  lastVerified: ControlledCoverageReport | null;
  selectedPlan?: { generation: string; approvalSha256: string; profileSha256: string; operationId: string } | null;
  registrationSha256?: string | null;
  state: 'QUIESCING' | 'READY' | 'UNKNOWN';
};
function normalizeSourcePlan(sourcePlan?: MainPublicationSourcePlan): { metadata?: SourcePlanMetadata; approval?: () => void;
  runnerApprovals?: Map<string, OriginalCIRunnerPlan['assertEffectApproved']> } {
  if (sourcePlan) {
      if (!/^[A-Za-z0-9_-]{1,100}$/.test(sourcePlan.operationId) || !sourcePlan.worker?.definition)
        fail('SOURCE_PLAN');
      const ci = sourcePlan.ci;
      const held = sourcePlan.ownerSource;
      const original = sourcePlan.originalSources;
      const runners = sourcePlan.ciRunners;
      if (original && (!Array.isArray(original) || original.length < 1 || original.length > 16 ||
          new Set(original.map(x => x.runtimeDirectory)).size !== original.length ||
          original.some(x => !Array.isArray(x.owners)) ||
          original.reduce((count, x) => count + x.owners.length, 0) > 64 ||
          new Set(original.flatMap((x: PinnedPublicationResidentSource) => x.owners.map(y => y.instanceId))).size !==
            original.reduce((count, x) => count + x.owners.length, 0))) fail('SOURCE_PLAN');
      const ciOwners = original?.flatMap(x => x.owners).filter(x => x.sourceScope === 'REGISTERED_CI_PRODUCER') ?? [];
      if (runners && (!Array.isArray(runners) || !runners.length || runners.length > 64 ||
          new Set(runners.map(x => x.instanceId)).size !== runners.length)) fail('SOURCE_PLAN');
      if (ciOwners.length !== (runners?.length ?? 0) || ciOwners.some(x => !runners?.some(y => y.instanceId === x.instanceId)))
        fail('SOURCE_PLAN');
      const runnerApprovals = new Map<string, OriginalCIRunnerPlan['assertEffectApproved']>();
      for (const runner of runners ?? []) {
        if (!opaque(runner.instanceId) || typeof runner.assertEffectApproved !== 'function' ||
            !Array.isArray(runner.effects) || !runner.effects.length || runner.effects.length > 64 ||
            Object.keys(runner).sort().join(',') !== 'assertEffectApproved,effects,instanceId') fail('SOURCE_PLAN');
        const ids = runner.effects.map((effect: OriginalCIEffectDescriptor) => originalCIEffectPlanIdentity(effect));
        if (new Set(ids).size !== ids.length ||
            new Set(runner.effects.map(originalCIEffectTarget)).size !== ids.length) fail('SOURCE_PLAN');
        runnerApprovals.set(runner.instanceId, runner.assertEffectApproved);
      }
      if (held && (Object.keys(held).sort().join(',') !== 'definitionDigest,instanceId,profileId' ||
          !opaque(held.instanceId) || !validHash(held.definitionDigest) ||
          !['canonical-producer', 'core.monitor.publish'].includes(held.profileId))) fail('SOURCE_PLAN');
      if (ci && (!opaque(ci.instanceId) || !/^[a-f0-9]{40}$/.test(ci.head) ||
          !validHash(ci.workflowSha256) || typeof ci.assertDispatchApproved !== 'function'))
        fail('SOURCE_PLAN');
      const metadata: SourcePlanMetadata = structuredClone({ operationId: sourcePlan.operationId, worker: sourcePlan.worker,
        ...(held ? { ownerSource: held } : {}),
        ...(original ? { originalSources: original } : {}),
        ...(runners ? { ciRunners: runners.map(x => ({ instanceId: x.instanceId, effects: x.effects })) } : {}),
        ...(ci ? { ci: { instanceId: ci.instanceId, head: ci.head, workflowSha256: ci.workflowSha256 } } : {}) });
      return { metadata, approval: ci?.assertDispatchApproved, runnerApprovals };
    }
  return {};
}
function validateCoverageConfiguration(profile: FixedCoverageProfile, sourcePlan?: SourcePlanMetadata) {
  const r = profile.registration;
    if (
      !validHash(r.rootIdentity) ||
      !validHash(r.rootDefinitionDigest) ||
      !validHash(r.deviceScopeRef) ||
      !validHash(r.inventoryDigest) ||
      !Array.isArray(r.instances) ||
      !Array.isArray(profile.instances) ||
      r.instances.length !== profile.instances.length ||
      r.instances.length < 7 ||
      r.instances.length > 64
    )
      fail('PROFILE');
    const ids = r.instances.map((x) => x.instanceId);
    if (new Set(ids).size !== ids.length || sha([...ids].sort()) !== r.registrationSetDigest)
      fail('MEMBERSHIP');
    for (const x of r.instances) {
      const p = profile.instances.filter((v) => v.instanceId === x.instanceId);
      if (
        !opaque(x.instanceId) ||
        !validHash(x.entryDefinitionDigest) ||
        !coverageEntries.includes(x.entryId) ||
        p.length !== 1 ||
        p[0].entryId !== x.entryId
      )
        fail('PROFILE');
    }
    if (coverageEntries.some((id) => !r.instances.some((x) => x.entryId === id)))
      fail('MEMBERSHIP');
    for (const x of profile.instances) {
      if (
        !['owned-release', 'foreign-controller'].includes(x.origin) ||
        !['GUARDED', 'NATIVE_NAMESPACE_DENIED', 'RETIRED_FENCED'].includes(x.state)
      )
        fail('PROFILE');
      if (
        [
          'canonical-producer',
          'generic-direct',
          'shared-transaction',
          'native-main-dispatch',
        ].includes(x.entryId) &&
        x.state !== 'GUARDED'
      )
        fail('REQUIRED_GUARD');
      if (x.origin === 'owned-release' && x.state === 'RETIRED_FENCED')
        fail('RETIREMENT_SOURCE_REQUIRED');
      if (
        x.origin === 'owned-release' &&
        profile.registration.instances.find((i) => i.instanceId === x.instanceId)!
          .entryDefinitionDigest !== coverageEntryDefinition(x.entryId, profile.source.files)
      )
        fail('ENTRY_DEFINITION');
    }
    if (sourcePlan?.ci) {
      const expected = profile.instances.find(x => x.instanceId === sourcePlan!.ci!.instanceId);
      if (!expected || expected.origin !== 'foreign-controller' || expected.entryId !== 'worksheet-ci' ||
          expected.state !== 'NATIVE_NAMESPACE_DENIED') fail('CI_SOURCE_PLAN');
    }
}
const drivers = new WeakSet<object>();
export function isManagedCoverageDriver(x: unknown): x is ManagedCoverageDriver {
  return !!x && typeof x === 'object' && drivers.has(x);
}
export class ManagedCoverageDriver implements ControlledCoverageDriver {
  readonly issuerId = randomUUID();
  readonly registration: CoverageRegistration;
  private readonly boot = randomUUID();
  private profile: FixedCoverageProfile;
  private readonly profileHash: string;
  private readonly key = sha('publication-coverage-driver/v1');
  private closed = true;
  private fence?: string;
  private leaseUntil = 0;
  private epoch = 0;
  private lastClock = 0;
  private accepted?: ControlledCoverageReport;
  private sourcePlan?: SourcePlanMetadata;
  private sourceApproval?: () => void;
  private runnerApprovals = new Map<string, OriginalCIRunnerPlan['assertEffectApproved']>();
  private sourceBroker?: RestrictedPublicationCISourceBroker;
  private originalSources: RestrictedPublicationResidentSource[] = [];
  private ownerRegistry?: RestrictedPublicationOwnerRegistry;
  private heldOwner?: { owner: RestrictedPublicationOwnerSource; handle: object };
  private lastHeldDiagnostics?: ReturnType<RestrictedPublicationOwnerSource['diagnostics']>;
  private sourceReceipts?: { definition: object; ci?: object };
  private sourceCleanup?: Promise<void>;
  private readonly generationPlans = new Map<string, MainPublicationGenerationPlan>();
  private readonly generationPlanHashes = new Map<string, string>();
  private initialPlanHash = '';
  private initialOperationId?: string;
  private activePlanHash = '';
  private pendingCutover?: { generation: string; handle: object; plan: MainPublicationGenerationPlan; epoch: number };
  private lastSourceDiagnostics?: ReturnType<RestrictedPublicationCISourceBroker['diagnostics']>;
  constructor(
    private readonly store: Store,
    private readonly plugin: string,
    readonly accountScopeRef: string,
    readonly controller: ManagedPublicationController,
    profile: FixedCoverageProfile,
    private readonly ownerCurrent: () => void,
    private readonly now: () => number = Date.now,
    sourcePlan?: MainPublicationSourcePlan,
  ) {
    if (
      !validHash(accountScopeRef) ||
      controller.accountScopeRef !== accountScopeRef ||
      !opaque(plugin) ||
      !(controller instanceof ManagedPublicationController)
    )
      fail('SCOPE');
    this.profile = structuredClone(profile);
    const configured = normalizeSourcePlan(sourcePlan);
    this.sourcePlan = configured.metadata;
    this.sourceApproval = configured.approval;
    this.runnerApprovals = configured.runnerApprovals ?? new Map();
    this.registration = structuredClone(this.profile.registration);
    validateCoverageConfiguration(this.profile, this.sourcePlan);
    this.activePlanHash = this.sourcePlan ? sha({ profile: this.profile, sourcePlan: this.sourcePlan }) : sha(this.profile);
    this.initialPlanHash = this.activePlanHash;
    this.initialOperationId = this.sourcePlan?.operationId;
    const claimed = new Set(this.sourcePlan?.originalSources?.flatMap(x => x.owners.map(y => y.instanceId)) ?? []);
    const currentMembers = new Set(this.profile.instances.map(x => x.instanceId));
    const operations = new Set(this.sourcePlan ? [this.sourcePlan.operationId] : []);
    if (sourcePlan?.generations && (!Array.isArray(sourcePlan.generations) || sourcePlan.generations.length > 16 ||
        !this.sourcePlan?.originalSources)) fail('GENERATION_PLANS');
    for (const candidate of sourcePlan?.generations ?? []) {
      if (!opaque(candidate.generation) || this.generationPlans.has(candidate.generation) ||
          (candidate.sourcePlan as MainPublicationSourcePlan).generations !== undefined) fail('GENERATION_PLANS');
      const plan = clonePublicationGenerationPlan(candidate);
      const next = normalizeSourcePlan(plan.sourcePlan);
      validateCoverageConfiguration(plan.profile, next.metadata);
      if (!next.metadata?.originalSources || operations.has(next.metadata.operationId) ||
          plan.profile.registration.deviceScopeRef !== this.profile.registration.deviceScopeRef) fail('GENERATION_PLANS');
      operations.add(next.metadata.operationId);
      for (const member of plan.profile.instances) {
        if (currentMembers.has(member.instanceId)) fail('INSTANCE_PLAN_REUSED');
        currentMembers.add(member.instanceId);
      }
      for (const source of next.metadata.originalSources) for (const owner of source.owners) {
        if (claimed.has(owner.instanceId)) fail('INSTANCE_PLAN_REUSED');
        claimed.add(owner.instanceId);
      }
      this.generationPlans.set(plan.generation, plan);
      this.generationPlanHashes.set(plan.generation, publicationGenerationPlanIdentity(plan));
    }
    this.profileHash = this.expectedProfileHash();
    drivers.add(this);
  }
  private expectedProfileHash() {
    const actual = this.sourcePlan ? sha({ profile: this.profile, sourcePlan: this.sourcePlan }) : sha(this.profile);
    if (actual !== this.activePlanHash || [...this.generationPlans].some(([generation, plan]) =>
        publicationGenerationPlanIdentity(plan) !== this.generationPlanHashes.get(generation))) fail('PROFILE_CHANGED');
    return this.generationPlans.size ? sha({ initial: this.initialPlanHash,
      generations: [...this.generationPlanHashes].sort(([a], [b]) => a.localeCompare(b)) }) : this.initialPlanHash;
  }
  private generationBinding(generation: string) {
    const candidate = this.generationPlans.get(generation);
    if (candidate) {
      const metadata = normalizeSourcePlan(candidate.sourcePlan).metadata!;
      return { generation, approvalSha256: this.generationPlanHashes.get(generation)!,
        profileSha256: sha({ profile: candidate.profile, sourcePlan: metadata }), operationId: metadata.operationId };
    }
    return { generation, approvalSha256: this.initialPlanHash, profileSha256: this.initialPlanHash,
      operationId: this.initialOperationId! };
  }
  private stopSource(retainOriginals = false) {
    const broker = this.sourceBroker;
    const held = this.heldOwner;
    const originals = retainOriginals ? [] : this.originalSources;
    const registry = this.ownerRegistry;
    this.sourceBroker = undefined;
    this.heldOwner = undefined;
    if (!retainOriginals) this.originalSources = [];
    this.ownerRegistry = undefined;
    this.sourceReceipts = undefined;
    if (!broker && !held && !registry && originals.length === 0) return;
    const previous = this.sourceCleanup;
    const tasks: Promise<void>[] = [];
    if (broker) tasks.push(broker.revoke().finally(() => { this.lastSourceDiagnostics = broker.diagnostics(); }));
    if (held) tasks.push(held.owner.revoke().finally(() => { this.lastHeldDiagnostics = held.owner.diagnostics(); }));
    if (registry) tasks.push(registry.revoke());
    for (const original of originals) tasks.push(original.revoke());
    const closing = Promise.allSettled(tasks).then(results => {
      const failure = results.find(x => x.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
    });
    this.sourceCleanup = previous ? Promise.all([previous, closing]).then(() => {}) : closing;
    void this.sourceCleanup.catch(() => {});
  }
  private async drainSource() {
    const pending = this.sourceCleanup;
    if (!pending) return;
    await pending;
    if (this.sourceCleanup === pending) this.sourceCleanup = undefined;
  }
  sourceDiagnostics() {
    return this.sourceBroker?.diagnostics() ?? this.lastSourceDiagnostics ?? null;
  }
  heldSourceDiagnostics() {
    return this.heldOwner?.owner.diagnostics() ?? this.lastHeldDiagnostics ?? null;
  }
  private async acquireSources(root: string, generation: string, epoch: number) {
    const plan = this.sourcePlan!;
    // A plan names the immutable tree we actually installed. It cannot substitute
    // the original checkout or a different interpreter for the loaded source.
    if (plan.worker.root !== root ||
        canonicalDigest(plan.worker.files) !== canonicalDigest(this.profile.source.files) ||
        canonicalDigest(plan.worker.python) !== canonicalDigest(this.profile.source.python))
      fail('SOURCE_RELEASE_BINDING');
    let lifecycle: object | undefined;
    const currentBinding = () => {
      this.ownerCurrent();
      if (epoch !== this.epoch) fail('REVOKED');
      return lifecycle ? readManagedLifecycleReceipt(lifecycle, this.controller).binding :
        this.controller.currentSourceBinding();
    };
    let preparedBroker: RestrictedPublicationCISourceBroker | undefined;
    const managedMembers = new Map<string, object>();
    if (plan.originalSources) {
      preparedBroker = await RestrictedPublicationCISourceBroker.prepareOwned(
        this.store, this.plugin, plan.operationId, plan.worker, currentBinding(), currentBinding);
      if (epoch !== this.epoch) { await preparedBroker.revoke(); fail('REVOKED'); }
      this.sourceBroker = preparedBroker;
      const expectations = preparedBroker.preparedDefinitionExpectations();
      // All canonical probes precede the retained LOADED lifecycle handle.
      // A later probe must never invalidate the source sequence underneath C.
      for (const member of expectations.instances) {
        if (expectations.censusSources.find(x => x.sourceId === member.censusSourceId)?.kind === 'managed' &&
            member.entryId !== 'worksheet-ci' && member.state !== 'RETIRED_FENCED')
          managedMembers.set(member.instanceId, await this.controller.probeEnrollment(this.profile.source, member.entryId));
      }
    }
    lifecycle = await this.controller.produceLifecycle('LOADED');
    const fact = readManagedLifecycleReceipt(lifecycle, this.controller);
    if (fact.operationId !== plan.operationId || fact.root !== root ||
        fact.binding.generation !== generation || fact.binding.accountId !== this.accountScopeRef ||
        fact.binding.deviceId !== this.registration.deviceScopeRef || fact.ownedJobs !== 0 ||
        fact.unresolvedAdmissions !== 0 || fact.unknownNativeEffects !== 0) fail('SOURCE_LIFECYCLE');
    const broker = preparedBroker ?? await RestrictedPublicationCISourceBroker.prepareOwned(
      this.store, this.plugin, plan.operationId, plan.worker, fact.binding, currentBinding,
    );
    if (epoch !== this.epoch) {
      await broker.revoke();
      this.lastSourceDiagnostics = broker.diagnostics();
      fail('REVOKED');
    }
    this.sourceBroker = broker;
    let brokerActive = false;
    const activateBroker = async () => {
      if (brokerActive) return;
      await broker.activatePrepared();
      if (epoch !== this.epoch) fail('REVOKED');
      broker.attachOwnedLifecycle(lifecycle!, this.controller);
      brokerActive = true;
    };
    let ciHandle: object | undefined;
    if (plan.originalSources) {
      if (!this.store.capturePublicationOwnerHistory || !this.store.assertPublicationOwnerHistoryCurrent)
        fail('ORIGINAL_HISTORY_SOURCE_REQUIRED');
      const sourceStore = this.store as Parameters<typeof RestrictedPublicationOwnerRegistry.startOwned>[0];
      const runnerPeers: Array<{ source: RestrictedPublicationResidentSource; handle: object;
        plan: Pick<OriginalCIRunnerPlan, 'instanceId' | 'effects'> }> = [];
      const profile = broker.preparedDefinitionExpectations();
      const registry = await RestrictedPublicationOwnerRegistry.startOwned(sourceStore, this.plugin,
        plan.operationId, profile, this.controller, lifecycle);
      if (epoch !== this.epoch) { await registry.revoke(); fail('REVOKED'); }
      this.ownerRegistry = registry;
      // Only actual Main-owned enrollment handles can cover managed members.
      // A role/profile or an original listener child is never substituted.
      for (const member of profile.instances) {
        const kind = profile.censusSources.find(x => x.sourceId === member.censusSourceId)?.kind;
        if (kind === 'managed' && member.entryId !== 'worksheet-ci' && member.state !== 'RETIRED_FENCED') {
          const enrolled = managedMembers.get(member.instanceId);
          if (!enrolled) fail('MANAGED_SOURCE_REQUIRED');
          await registry.bindManaged(member.instanceId, enrolled);
        }
      }
      for (const source of plan.originalSources) {
        const owner = await RestrictedPublicationResidentSource.startOwned(sourceStore, this.plugin,
          plan.operationId, source, fact.binding, currentBinding);
        if (epoch !== this.epoch) { await owner.revoke(); fail('REVOKED'); }
        this.originalSources.push(owner);
      }
      for (const owner of this.originalSources) {
        const expected = plan.originalSources[this.originalSources.indexOf(owner)];
        for (let index = 0; index < expected.owners.length; index++) {
          let peer = await owner.acceptOriginal();
          const actual = readOriginalPublicationPeerReceipt(peer, owner);
          if (actual.sourceScope === 'RESIDENT_ORIGINAL_ENTRY') {
            const member = profile.instances.find(x => x.instanceId === actual.instanceId);
            if (!member) fail('ORIGINAL_MEMBER_UNREGISTERED');
            if (member.state === 'RETIRED_FENCED') {
              peer = await owner.transition(peer, 'fence');
              peer = await owner.transition(peer, 'drain');
              peer = await owner.transition(peer, 'retire');
            }
            await registry.bindOriginal(actual.instanceId, owner, peer);
          } else if (actual.sourceScope === 'REGISTERED_CI_PRODUCER') {
            const runner = plan.ciRunners?.find(x => x.instanceId === actual.instanceId);
            if (!runner || !this.runnerApprovals.has(actual.instanceId)) fail('CI_RUNNER_PLAN_REQUIRED');
            runnerPeers.push({ source: owner, handle: peer, plan: runner });
          } else {
            peer = await owner.transition(peer, 'fence');
            peer = await owner.transition(peer, 'drain');
            if (actual.sourceScope === 'REGISTERED_NAMESPACE_OWNER')
              await registry.bindNamespace(actual.ownerId, owner, peer);
            else if (actual.sourceScope === 'REGISTERED_RESIDENT_NONPUBLISHER')
              await registry.bindNonPublisher(actual.ownerId, owner, peer);
            else fail('ORIGINAL_SCOPE');
          }
        }
      }
      // This real preflight precedes the only dispatch approval callback.
      // Missing census/history/namespace producers leave approval count zero.
      let sourcePreflight = await registry.preflightNonCI();
      const assertPreflight = () => {
        this.ownerCurrent(); if (epoch !== this.epoch) fail('REVOKED');
        readOriginalPublicationRegistrySeal(sourcePreflight, registry);
      };
      // No original runner preparation, registration token, configuration or launch
      // precedes the real source preflight. Workflow history remains a separate
      // mandatory owner source; these runner receipts cannot satisfy it.
      const advanced: Array<{ source: RestrictedPublicationResidentSource; instanceId: string;
        producer: RestrictedPublicationCIProducer;
        result: Awaited<ReturnType<RestrictedPublicationCIProducer['advanceUntilPark']>> }> = [];
      for (const runner of runnerPeers) {
        const approval = this.runnerApprovals.get(runner.plan.instanceId)!;
        const producer = RestrictedPublicationCIProducer.fromOriginal(sourceStore, this.plugin,
          runner.source, runner.handle, { ...runner.plan, assertEffectApproved: async effect => {
            assertPreflight();
            await approval(effect);
            assertPreflight();
          } });
        advanced.push({ source: runner.source, instanceId: runner.plan.instanceId,
          producer, result: await producer.advanceUntilPark() });
      }
      // Dispatch B while the original runner is at its acknowledged start
      // boundary. Both long observations then share one finite park/resume;
      // no early B pending object or non-CI lease ages through the whole job.
      let ciObservation: object | undefined;
      if (plan.ci) {
        await activateBroker();
        await broker.dispatchOriginalCI(plan.ci.head, plan.ci.workflowSha256, () => {
          assertPreflight(); this.sourceApproval!(); assertPreflight();
        });
        ciObservation = await broker.parkOriginalCI();
      }
      let refreshed: ReadonlyMap<RestrictedPublicationResidentSource, ReadonlyMap<string, object>> | undefined;
      if (ciObservation || advanced.some(x => x.result.state === 'PARK_READY')) {
        const registryObservation = await registry.beginObservation();
        const parked: Array<{ source: RestrictedPublicationResidentSource; handle: object }> = [];
        for (const source of this.originalSources) {
          const checkpoints = advanced.filter(x => x.source === source).flatMap(x =>
            x.result.state === 'PARK_READY' ? [x.result.checkpoint] : []);
          parked.push({ source, handle: await source.parkForObservation(checkpoints) });
        }
        await Promise.all([
          ...parked.map(x => x.source.waitForObservation(x.handle)),
          ...(ciObservation ? [broker.waitForOriginalCI(ciObservation)] : []),
        ]);
        this.ownerCurrent(); if (epoch !== this.epoch) fail('REVOKED');
        // Every original owner has finished its passive observation. Resume
        // all actual sources before any cleanup/drain claim is allowed.
        const next = new Map<RestrictedPublicationResidentSource, ReadonlyMap<string, object>>();
        for (const held of parked) next.set(held.source, await held.source.resumeAfterObservation(held.handle));
        refreshed = next;
        await registry.finishObservation(registryObservation, refreshed);
        if (ciObservation) await broker.resumeOriginalCI(ciObservation, () => {
          this.ownerCurrent(); if (epoch !== this.epoch) fail('REVOKED');
          this.sourceApproval!();
          this.ownerCurrent(); if (epoch !== this.epoch) fail('REVOKED');
        });
        sourcePreflight = await registry.preflightNonCI();
      }
      for (const runner of advanced) {
        let peer = refreshed?.get(runner.source)?.get(runner.instanceId) ?? runner.result.handle;
        if (runner.result.state === 'PARK_READY') {
          if (!refreshed) fail('CI_OBSERVATION_REQUIRED');
          peer = await runner.producer.finishAfterObservation(runner.result.checkpoint, peer);
        }
        peer = await runner.source.transition(peer, 'fence');
        peer = await runner.source.transition(peer, 'drain');
        await runner.source.transition(peer, 'retire');
      }
      await activateBroker();
      if (plan.ci) {
        ciHandle = await broker.inspectCI();
        const inventory = await broker.inspectCIInventory();
        await registry.bindCIFromBroker(plan.ci.instanceId, broker, ciHandle, inventory);
      }
      broker.attachOwnerRegistry(registry, await registry.seal());
    }
    await activateBroker();
    // This additional diagnostic owner supplies no census authority. Start its
    // own short lease only when C is ready to read, after all long observations.
    if (plan.ownerSource) {
      const owner = await RestrictedPublicationOwnerSource.startOwned(this.store, this.plugin, plan.operationId, {
        root, files: plan.worker.files, python: plan.worker.python, sourceDigest: fact.sourceDigest,
        ...plan.ownerSource,
      }, fact.binding, currentBinding);
      try {
        if (epoch !== this.epoch) fail('REVOKED');
        this.heldOwner = { owner, handle: owner.loadedReceipt() };
        readHeldPublicationOwnerReceipt(this.heldOwner.handle, owner);
      } catch (error) {
        await owner.revoke();
        throw error;
      }
    }
    // Missing original census/member/namespace owners closes before any dispatch.
    const handle = await broker.inspectDefinition();
    const definition = readPublicationSourceReceipt(handle, broker);
    this.validateDefinition(definition, fact, generation);
    this.sourceReceipts = { definition: handle, ...(ciHandle ? { ci: ciHandle } : {}) };
    return { broker, definition, fact };
  }
  private validateDefinition(value: Record<string, any>, fact: Readonly<ManagedLifecycleObservation>, generation: string) {
    const { receiptDigest, ...observed } = value;
    if (value.schema !== 'publication-definition-receipt/v1' ||
        value.scope !== 'REGISTERED_DEFINITION_SOURCES_ONLY' ||
        value.operationId !== fact.operationId || canonicalDigest(value.binding) !== canonicalDigest(fact.binding) ||
        value.releaseGeneration !== generation || value.releaseSequence !== fact.releaseSequence ||
        value.lifecycleSequence !== fact.lifecycleSequence || !validHash(receiptDigest) ||
        canonicalDigest(observed) !== receiptDigest || !opaque(value.fenceRef) ||
        !validHash(value.enrollmentReceiptId) || value.oldGenerationAdmissions?.unresolved !== 0 ||
        !opaque(value.oldGenerationAdmissions?.fenceReceiptId) || value.unknownNativeEffects !== 0 ||
        !Array.isArray(value.receiptIds) || value.receiptIds.some((x: unknown) => !opaque(x)) ||
        new Set(value.receiptIds).size !== value.receiptIds.length ||
        !validHash(value.receiptBindingsSha256) || !validHash(value.residentSnapshotSha256) ||
        !Array.isArray(value.members) || !Array.isArray(value.exclusions)) fail('DEFINITION_FACTS');
    const wanted = this.profile.instances.filter(x => x.origin === 'foreign-controller');
    if (this.sourcePlan?.ci && !value.members.some((x: any) => x?.instanceId === this.sourcePlan!.ci!.instanceId))
      fail('CI_MEMBER_PROJECTION_UNSUPPORTED');
    if (value.members.length !== wanted.length ||
        new Set(value.members.map((x: any) => x?.instanceId)).size !== value.members.length)
      fail('DEFINITION_MEMBERSHIP');
    for (const member of value.members) {
      const expected = wanted.find(x => x.instanceId === member?.instanceId);
      const registered = this.registration.instances.find(x => x.instanceId === member?.instanceId);
      if (!expected || !registered || member.entryId !== expected.entryId || member.state !== expected.state ||
          member.entryDefinitionDigest !== registered.entryDefinitionDigest || member.releaseGeneration !== generation ||
          !opaque(member.launchAuthorityId) || !opaque(member.admissionReceiptId) ||
          !validHash(member.guardSourceIdentity) || !Number.isSafeInteger(member.effectFenceRevision) ||
          member.effectFenceRevision < 1 ||
          (member.state === 'GUARDED' ? member.dispositionReceiptId !== null : !opaque(member.dispositionReceiptId)))
        fail('DEFINITION_MEMBERSHIP');
    }
    if (value.exclusions.length !== adjacentCoverageEntries.length || adjacentCoverageEntries.some(entryId => {
      const matching = value.exclusions.filter((x: any) => x?.entryId === entryId);
      return matching.length !== 1 || !opaque(matching[0].receiptId) || !validHash(matching[0].definitionDigest) ||
        !Number.isSafeInteger(matching[0].fenceRevision) || matching[0].fenceRevision < 1;
    })) fail('DEFINITION_NAMESPACES');
  }
  private async inspectSourceCI(broker: RestrictedPublicationCISourceBroker, definition: Record<string, any>) {
    const plan = this.sourcePlan!;
    if (!plan.ci) {
      if (this.profile.instances.some(x => x.origin === 'foreign-controller' && x.entryId === 'worksheet-ci'))
        fail('CI_SOURCE_REQUIRED');
      return undefined;
    }
    // B's one-run denial has no global census/fence/authority fields. Require C's
    // independently held exact registered member; B corroborates only this run.
    const member = definition.members.find((x: any) => x.instanceId === plan.ci!.instanceId);
    if (!member || member.entryId !== 'worksheet-ci' || member.state !== 'NATIVE_NAMESPACE_DENIED')
      fail('CI_MEMBER_PROJECTION_UNSUPPORTED');
    const handle = this.sourceReceipts?.ci;
    if (!handle) fail('CI_SOURCE_NOT_ACQUIRED');
    const value = readPublicationSourceReceipt(handle, broker);
    if (value.consumer !== 'worksheet-ci' || value.head_sha !== plan.ci.head ||
        value.workflow_sha256 !== plan.ci.workflowSha256) fail('CI_SOURCE_BINDING');
    this.sourceReceipts!.ci = handle;
    return value;
  }
  private clock() {
    const t = this.now();
    if (!Number.isSafeInteger(t) || t < this.lastClock) {
      this.close();
      fail('CLOCK');
    }
    this.lastClock = t;
    return t;
  }
  private close() {
    this.closed = true;
    this.epoch++;
    this.leaseUntil = 0;
    this.stopSource();
  }
  assertCurrent(fenceRef?: string) {
    try {
      this.ownerCurrent();
      if (this.expectedProfileHash() !== this.profileHash) fail('PROFILE_CHANGED');
      const t = this.clock();
      // Authority calls current() during quiesce/install, before a business lease exists.
      // A supplied effect fence always requires a completed current report.
      if (fenceRef !== undefined && (this.closed || fenceRef !== this.fence || t >= this.leaseUntil))
        fail('LEASE_CLOSED');
      if (!this.closed && this.accepted) {
        this.controller.assertCurrent(this.accepted.members.length ? this.activeRoot! : '');
        if (this.sourcePlan && (!this.sourceBroker || !this.sourceReceipts)) fail('SOURCE_CLOSED');
        if (this.sourcePlan?.ownerSource) {
          if (!this.heldOwner) fail('SOURCE_CLOSED');
          readHeldPublicationOwnerReceipt(this.heldOwner.handle, this.heldOwner.owner);
        }
        this.sourceBroker?.assertCurrent();
      }
    } catch (error) { this.close(); throw error; }
  }
  private activeRoot?: string;
  private async read() {
    const row = await this.store.readConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
    );
    this.ownerCurrent();
    if (!row)
      return {
        row,
        value: {
          schema: 'publication-coverage-driver/v1',
          boot: this.boot,
          account: this.accountScopeRef,
          profile: this.profileHash,
          releaseSequence: 0,
          lifecycleSequence: 0,
          usedGenerations: [],
          lastVerified: null,
          ...(this.generationPlans.size ? { selectedPlan: null, registrationSha256: null } : {}),
          state: 'QUIESCING',
        } as DriverState,
      };
    let v: DriverState;
    try {
      v = JSON.parse(row.payload);
    } catch {
      fail('LEDGER');
    }
    if (
      v!.schema !== 'publication-coverage-driver/v1' ||
      v!.account !== this.accountScopeRef ||
      v!.profile !== this.profileHash ||
      !Number.isSafeInteger(v!.releaseSequence) ||
      !Number.isSafeInteger(v!.lifecycleSequence) ||
      v!.releaseSequence < 0 ||
      v!.lifecycleSequence < 0 ||
      !Array.isArray(v!.usedGenerations)
    )
      fail('LEDGER');
    if (this.generationPlans.size) {
      if (v!.selectedPlan === null) {
        if (v!.usedGenerations.length || v!.state === 'READY') fail('GENERATION_LEDGER');
      } else {
        const selected = v!.selectedPlan;
        if (!selected || !opaque(selected.generation) || !v!.usedGenerations.includes(selected.generation) ||
            canonicalDigest(selected) !== canonicalDigest(this.generationBinding(selected.generation)) ||
            (v!.state === 'READY' && (!validHash(v!.registrationSha256) ||
              v!.lastVerified?.releaseGeneration !== selected.generation))) fail('GENERATION_LEDGER');
      }
    }
    return { row, value: v! };
  }
  private async save(old: Awaited<ReturnType<ManagedCoverageDriver['read']>>, value: DriverState) {
    if (
      !(await this.store.compareAndSwapConsumerGuardReceipt(
        this.plugin,
        this.accountScopeRef,
        this.key,
        old.row,
        JSON.stringify(value),
      ))
    ) {
      this.close();
      fail('CAS');
    }
    this.ownerCurrent();
  }
  async quiesce(nextGeneration?: string) {
    const registry = this.ownerRegistry;
    const nextPlan = nextGeneration === undefined ? undefined : this.generationPlans.get(nextGeneration);
    if (this.pendingCutover) {
      this.pendingCutover = undefined;
      this.close();
      await this.drainSource();
      fail('CUTOVER_ALREADY_PREPARED');
    }
    let retirement: object | undefined;
    // Synchronously close effect admission, while retaining the original source
    // generation long enough to collect actual peer retirement acknowledgments.
    this.closed = true;
    this.leaseUntil = 0;
    if (nextPlan) {
      try {
        if (!registry || !this.originalSources.length || !this.store.capturePublicationOwnerHistory ||
            !this.store.assertPublicationOwnerHistoryCurrent) fail('ORIGINAL_CUTOVER_SOURCE_REQUIRED');
        const sourceStore = this.store as Parameters<typeof preparePublicationGenerationCutover>[1];
        await assertNoUncertainPublicationCutover(sourceStore, this.plugin, this.accountScopeRef);
        retirement = await registry.prepareRetirement();
        const retained = await registry.retainPolicyCutovers(retirement);
        if (retained.length !== this.originalSources.length ||
            this.originalSources.some(source => !retained.some(x => x.source === source))) fail('CUTOVER_OWNER_SET');
        // The old source binding has now been converted into terminal-only
        // private capabilities. Revoking ordinary authority cannot retain work.
        const epoch = ++this.epoch;
        this.stopSource(true);
        const results = await Promise.allSettled([this.drainSource(), this.controller.revoke()]);
        const failure = results.find(x => x.status === 'rejected');
        if (failure?.status === 'rejected') throw failure.reason;
        await this.controller.drain();
        const drained = await this.controller.produceLifecycle('DRAINED');
        const completed = await registry.completeRetirement(retirement, drained);
        const current = () => {
          this.ownerCurrent();
          if (epoch !== this.epoch || !this.closed || this.pendingCutover) fail('CUTOVER_REVOKED');
        };
        current();
        const handle = await preparePublicationGenerationCutover(this, sourceStore, this.plugin,
          this.controller, registry, completed, drained, retained, nextPlan, current);
        current();
        this.pendingCutover = { generation: nextGeneration!, handle, plan: nextPlan, epoch };
        this.stopSource();
        await this.drainSource();
        return;
      } catch (error) { this.close(); await this.drainSource(); throw error; }
    }
    if (nextGeneration !== undefined && registry && this.originalSources.length) {
      this.close(); await this.drainSource(); fail('GENERATION_PLAN_REQUIRED');
    }
    if (registry) {
      try { retirement = await registry.prepareRetirement(); }
      catch (error) { this.close(); await this.drainSource(); throw error; }
    }
    this.close();
    // Both local owners revoke synchronously before either durable cleanup waits.
    const results = await Promise.allSettled([this.drainSource(), this.controller.revoke()]);
    const failure = results.find(x => x.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
    await this.controller.drain();
    if (registry && retirement)
      await registry.completeRetirement(retirement, await this.controller.produceLifecycle('DRAINED'));
    const observed = await this.controller.coverageSourceState();
    if (observed.ownedJobs !== 0 || observed.unresolved !== 0) fail('UNRESOLVED');
    if ((await this.store.unknownNativePublicationEffects(this.plugin)) !== 0)
      fail('NATIVE_EFFECT_UNKNOWN');
  }
  async switchRelease(
    generation: string,
    previousSequence: number,
  ): Promise<ControlledCoverageReport> {
    const cutover = this.pendingCutover;
    if (cutover && (cutover.generation !== generation || cutover.epoch !== this.epoch)) {
      this.pendingCutover = undefined; this.close(); await this.drainSource(); fail('CUTOVER_GENERATION');
    }
    this.pendingCutover = undefined;
    this.close();
    const epoch = this.epoch;
    await this.drainSource();
    if (epoch !== this.epoch) fail('REVOKED');
    this.ownerCurrent();
    const old = await this.read();
    if (
      !opaque(generation) ||
      old.value.usedGenerations.includes(generation) ||
      old.value.usedGenerations.length >= 1024
    )
      fail('GENERATION');
    if (old.value.lifecycleSequence !== previousSequence) fail('SEQUENCE_GAP');
    if (this.sourcePlan?.originalSources && (old.value.state === 'UNKNOWN' ||
        (old.value.state === 'QUIESCING' && old.value.usedGenerations.length))) fail('PRIOR_GENERATION_UNKNOWN');
    if (this.generationPlans.size && !cutover && old.value.usedGenerations.length) fail('PRIVATE_CUTOVER_REQUIRED');
    if ((await this.store.unknownNativePublicationEffects(this.plugin)) !== 0)
      fail('NATIVE_EFFECT_UNKNOWN');
    const pending: DriverState = {
      ...old.value,
      boot: this.boot,
      state: 'QUIESCING',
      usedGenerations: [...old.value.usedGenerations, generation],
      ...(this.generationPlans.size ? { selectedPlan: this.generationBinding(generation), registrationSha256: null } : {}),
    };
    await this.save(old, pending);
    let transition = { row: { revision: (old.row?.revision ?? 0) + 1, payload: JSON.stringify(pending) }, value: pending };
    try {
      let release;
      if (cutover) {
        const committed = await commitPublicationGenerationCutover(cutover.handle, this, this.controller, generation, () => {
          this.ownerCurrent();
          if (epoch !== this.epoch || !this.closed) fail('CUTOVER_REVOKED');
        });
        if (epoch !== this.epoch) fail('REVOKED');
        const approved = this.generationPlans.get(generation);
        if (!approved || publicationGenerationPlanIdentity(committed.plan) !== this.generationPlanHashes.get(generation) ||
            publicationGenerationPlanIdentity(approved) !== publicationGenerationPlanIdentity(committed.plan)) fail('GENERATION_PLAN_CHANGED');
        this.profile = structuredClone(committed.plan.profile);
        const configured = normalizeSourcePlan(committed.plan.sourcePlan);
        this.sourcePlan = configured.metadata;
        this.sourceApproval = configured.approval;
        this.runnerApprovals = configured.runnerApprovals ?? new Map();
        validateCoverageConfiguration(this.profile, this.sourcePlan);
        for (const key of Object.keys(this.registration)) delete (this.registration as unknown as Record<string, unknown>)[key];
        Object.assign(this.registration, structuredClone(this.profile.registration));
        this.activePlanHash = this.sourcePlan ? sha({ profile: this.profile, sourcePlan: this.sourcePlan }) : sha(this.profile);
        if (pending.selectedPlan?.profileSha256 !== this.activePlanHash ||
            pending.selectedPlan?.operationId !== this.sourcePlan?.operationId) fail('GENERATION_LEDGER');
        this.expectedProfileHash();
        release = committed.release;
      } else {
        if (this.generationPlans.has(generation)) fail('PRIVATE_CUTOVER_REQUIRED');
        release = await this.controller.install(this.profile.source, generation, this.sourcePlan?.operationId);
      }
      const loaded = new Map<string, object>();
      // Reject unsupported foreign authority before changing the actual owned entry.
      if (!this.sourcePlan && this.profile.instances.some(x => x.origin !== 'owned-release')) fail('FOREIGN_SOURCE_UNSUPPORTED');
      if (epoch !== this.epoch) fail('REVOKED');
      // A switch invalidates prior enrollment. Only probes of the now ACTIVE entry
      // can attest to the loaded generation; INSTALLED probes cannot be carried over.
      await this.controller.switchEntry(generation);
      for (const x of this.profile.instances) {
        if (x.origin !== 'owned-release') continue;
        if (x.entryId === 'native-main-dispatch') continue;
        // Retired/denied roles execute only the fixed no-business guard probe, never their business main.
        loaded.set(
          x.instanceId,
          await this.controller.probeEnrollment(this.profile.source, x.entryId),
        );
      }
      if (this.sourcePlan && !this.profile.instances.some(x =>
          x.origin === 'owned-release' && x.entryId === 'canonical-producer')) {
        // This supplies only the installed controller's lifecycle observation;
        // it does not add a consumer to the registered membership/census.
        await this.controller.probeEnrollment(this.profile.source, 'canonical-producer');
      }
      if (epoch !== this.epoch) fail('REVOKED');
      this.activeRoot = release.root;
      if (
        !this.profile.publisher ||
        ![
          this.profile.publisher.artifactRoot,
          this.profile.publisher.queueRoot,
          this.profile.publisher.dispatchRoot,
        ].every((x) => path.isAbsolute(x))
      )
        fail('PUBLISHER_PROFILE');
      this.registration.rootIdentity = sha([
        this.accountScopeRef,
        this.registration.deviceScopeRef,
        generation,
        release.root,
        release.sourceDigest,
      ]);
      this.registration.rootDefinitionDigest = canonicalDigest([
        sha(this.profile.source.files),
        release.root,
        this.profile.publisher.artifactRoot,
        this.profile.publisher.queueRoot,
        this.profile.publisher.dispatchRoot,
        this.profile.publisher.publicOrigin,
        this.profile.source.files,
        this.profile.source.python,
      ]);
      const state = await this.controller.coverageSourceState();
      if (state.unresolved !== 0 || state.ownedJobs !== 0) fail('UNRESOLVED');
      const nativeUnknown = await this.store.unknownNativePublicationEffects(this.plugin);
      if (nativeUnknown !== 0) fail('NATIVE_EFFECT_UNKNOWN');
      const members: ControlledCoverageReport['members'] = this.profile.instances.filter(x => x.origin === 'owned-release').map((x) => {
        if (x.entryId === 'native-main-dispatch') {
          this.controller.assertCurrent(release.root);
          return {
            instanceId: x.instanceId,
            entryId: x.entryId,
            launchAuthorityId: this.issuerId,
            admissionReceiptId: sha([
              this.boot,
              release.root,
              state.boot,
              state.epoch,
              'main-current-kernel',
            ]),
            releaseGeneration: generation,
            guardSourceIdentity: this.registration.rootIdentity,
            entryDefinitionDigest: this.registration.instances.find(
              (i) => i.instanceId === x.instanceId,
            )!.entryDefinitionDigest,
            state: 'GUARDED' as const,
            effectFenceRevision: state.epoch + 1,
            dispositionReceiptId: null,
          };
        }
        const observation = readManagedEnrollmentReceipt(
          loaded.get(x.instanceId)!,
          this.controller,
        );
        if (
          observation.generation !== generation ||
          observation.accountScopeRef !== this.accountScopeRef ||
          observation.deviceScopeRef !== this.registration.deviceScopeRef ||
          observation.entryId !== x.entryId ||
          observation.inventoryDigest !== this.registration.inventoryDigest ||
          canonicalDigest({ entryId: x.entryId, files: observation.files }) !==
            this.registration.instances.find((i) => i.instanceId === x.instanceId)!
              .entryDefinitionDigest
        )
          fail('LOADED_BINDING');
        return {
          instanceId: x.instanceId,
          entryId: x.entryId,
          launchAuthorityId: this.issuerId,
          admissionReceiptId: sha(observation),
          releaseGeneration: generation,
          guardSourceIdentity: this.registration.rootIdentity,
          entryDefinitionDigest: this.registration.instances.find(
            (i) => i.instanceId === x.instanceId,
          )!.entryDefinitionDigest,
          state: x.state,
          effectFenceRevision: state.epoch + 1,
          dispositionReceiptId: x.state === 'GUARDED' ? null : sha(observation),
        };
      });
      const exclusions: ControlledCoverageReport['exclusions'] = [];
      if (
        !this.profile.namespaceOwnership ||
        Object.keys(this.profile.namespaceOwnership).sort().join(',') !==
          [...adjacentCoverageEntries].sort().join(',')
      )
        fail('NAMESPACE_SOURCE_UNKNOWN');
      let heldSources: { definition: Record<string, any>; lifecycle: Readonly<ManagedLifecycleObservation>; ci?: Record<string, any> } | undefined;
      if (this.sourcePlan) {
        const source = await this.acquireSources(release.root, generation, epoch);
        if (epoch !== this.epoch) fail('REVOKED');
        const ci = await this.inspectSourceCI(source.broker, source.definition);
        if (epoch !== this.epoch) fail('REVOKED');
        heldSources = { definition: source.definition, lifecycle: source.fact, ci };
        for (const member of source.definition.members) {
          const { instanceId, entryId, launchAuthorityId, admissionReceiptId, releaseGeneration,
            guardSourceIdentity, entryDefinitionDigest, state, effectFenceRevision, dispositionReceiptId } = member;
          members.push({ instanceId, entryId, launchAuthorityId, admissionReceiptId, releaseGeneration,
            guardSourceIdentity, entryDefinitionDigest, state, effectFenceRevision, dispositionReceiptId });
        }
        for (const sourceExclusion of source.definition.exclusions) {
          exclusions.push({ entryId: sourceExclusion.entryId, namespace: 'native-publication',
            fenceReceiptId: sourceExclusion.receiptId, definitionDigest: sourceExclusion.definitionDigest,
            fenceRevision: sourceExclusion.fenceRevision });
        }
        const current = await this.controller.coverageSourceState();
        if (current.epoch !== state.epoch || current.unresolved !== 0 || current.ownedJobs !== 0 ||
            (await this.store.unknownNativePublicationEffects(this.plugin)) !== 0) fail('SOURCE_FACTS_CHANGED');
      } else {
        // Source presence/probe does not prove remote/old namespace fences.
        const namespaceReceipt = await this.controller.probeEnrollment(
          this.profile.source,
          'owned-namespace-source',
        );
        const namespaceObservation = readManagedEnrollmentReceipt(namespaceReceipt, this.controller);
        if (namespaceObservation.generation !== generation) fail('NAMESPACE_BINDING');
        for (const entryId of adjacentCoverageEntries) {
          // This receipt covers ONLY the actual owned launcher. A real foreign producer
          // is deliberately not replaced by source hashes or self-supplied JSON.
          if (this.profile.namespaceOwnership[entryId] !== 'owned-launcher')
            fail('FOREIGN_NAMESPACE_SOURCE_UNSUPPORTED');
          const observation = readManagedEnrollmentReceipt(
            await this.controller.namespaceFence(this.profile.source, entryId),
            this.controller,
          );
          if (observation.entryId !== 'namespace:' + entryId || observation.generation !== generation)
            fail('NAMESPACE_BINDING');
          exclusions.push({
            entryId,
            namespace: 'native-publication',
            fenceReceiptId: sha(observation),
            definitionDigest: sha(observation.files),
            fenceRevision: state.epoch + 1,
          });
        }
      }
      if (members.length !== this.registration.instances.length ||
          new Set(members.map(x => x.instanceId)).size !== members.length ||
          this.registration.instances.some(x => !members.some(m => m.instanceId === x.instanceId &&
            m.entryId === x.entryId && m.entryDefinitionDigest === x.entryDefinitionDigest))) fail('MEMBERSHIP');
      const sourceBinding = heldSources ? canonicalDigest({
        lifecycle: heldSources.lifecycle,
        definitionReceiptDigest: heldSources.definition.receiptDigest,
        ci: heldSources.ci ?? null,
      }) : undefined;
      const report: ControlledCoverageReport = {
        releaseGeneration: generation,
        // Driver counts completed coverage transitions. Controller/C preserve their
        // separate install/switch/load counters in the retained source binding.
        releaseSequence: old.value.releaseSequence + 1,
        lifecycleSequence: old.value.lifecycleSequence + 1,
        fenceRef: sourceBinding ? canonicalDigest([this.boot, generation, state.epoch,
          heldSources!.definition.fenceRef, sourceBinding]) : sha([this.boot, generation, state.epoch]),
        enrollmentReceiptId: sourceBinding ? canonicalDigest([members, sourceBinding]) : sha(members),
        members,
        oldGenerationAdmissions: {
          unresolved: state.unresolved,
          fenceReceiptId: sourceBinding ? canonicalDigest([this.boot, state.epoch, 'drained',
            heldSources!.definition.oldGenerationAdmissions.fenceReceiptId, sourceBinding]) :
            sha([this.boot, state.epoch, 'drained']),
        },
        unknownNativeEffects: nativeUnknown,
        exclusions,
      };
      if (epoch !== this.epoch) fail('REVOKED');
      const ready: DriverState = {
        ...pending,
        state: 'READY',
        releaseSequence: report.releaseSequence,
        lifecycleSequence: report.lifecycleSequence,
        lastVerified: report,
        ...(this.generationPlans.size ? { registrationSha256: sha(this.registration) } : {}),
      };
      await this.save(transition, ready);
      transition = { row: { revision: transition.row.revision + 1, payload: JSON.stringify(ready) }, value: ready };
      this.accepted = structuredClone(report);
      this.fence = report.fenceRef;
      this.closed = false;
      this.leaseUntil = this.clock() + 30000;
      return structuredClone(report);
    } catch (error) {
      // An old asynchronous failure must not revoke or overwrite a newer switch.
      if (epoch === this.epoch) {
        this.close();
        const closedEpoch = this.epoch;
        try {
          const current = await this.read();
          if (closedEpoch === this.epoch && canonicalDigest(current.row) === canonicalDigest(transition.row))
            await this.save(transition, { ...transition.value, state: 'UNKNOWN' });
        } finally { await this.drainSource(); }
      }
      throw error;
    }
  }
  async refresh(): Promise<void> {
    const epoch = this.epoch;
    try {
      this.requireReady();
      const broker = this.sourceBroker;
      const receipts = this.sourceReceipts;
      const held = this.heldOwner;
      await this.controller.verifyCurrent(this.activeRoot!);
      if (epoch !== this.epoch) fail('REVOKED');
      if (this.sourcePlan) {
        if (!broker || !receipts) fail('SOURCE_CLOSED');
        if (this.sourcePlan.ownerSource) {
          if (!held) fail('SOURCE_CLOSED');
          await held.owner.current(held.handle);
          if (epoch !== this.epoch) fail('REVOKED');
        }
        // B owns a single sequenced channel. Each original private handle must
        // remain current; copied summary JSON cannot renew either source lease.
        await broker.current(receipts.definition);
        if (epoch !== this.epoch) fail('REVOKED');
        if (receipts.ci) await broker.current(receipts.ci);
      }
      const persisted = await this.read();
      if (epoch !== this.epoch || persisted.value.state !== 'READY' ||
          sha(persisted.value.lastVerified) !== sha(this.accepted)) fail('FACTS_CHANGED');
      if (this.generationPlans.size && (persisted.value.selectedPlan?.profileSha256 !== this.activePlanHash ||
          persisted.value.selectedPlan?.operationId !== this.sourcePlan?.operationId ||
          persisted.value.selectedPlan?.generation !== this.accepted?.releaseGeneration ||
          persisted.value.registrationSha256 !== sha(this.registration))) fail('GENERATION_LEDGER');
      // Release drain/UNKNOWN counts are measured before switching generations.
      // An admitted current operation deliberately persists UNKNOWN before remote IO;
      // its original Main action/job authority guards every effect and no-resubmit.
      this.requireReady();
      this.leaseUntil = this.clock() + 30000;
    } catch (error) {
      // A deferred old refresh can reject after a newer generation is ready.
      // Its failure must not close the new broker/lease. assertCurrent may have
      // already scheduled this generation's cleanup before throwing.
      if (epoch === this.epoch) this.close();
      await this.drainSource();
      throw error;
    }
  }
  publicationRoot(authority: ConsumerGuardCoverageAuthority): RegisteredPublicationRoot {
    this.requireReady();
    if (!this.activeRoot) fail('SOURCE_UNSUPPORTED');
    return {
      root: this.activeRoot,
      ...this.profile.publisher,
      sourceIdentity: sha(this.profile.source.files),
      files: { ...this.profile.source.files },
      python: { ...this.profile.source.python },
      consumerCoverage: authority,
      consumerRootIdentity: this.registration.rootIdentity,
      managedPublisher: {
        controller: this.controller,
        source: structuredClone(this.profile.source),
      },
      assertConsumerGuards: async () => {
        await this.refresh();
      },
    };
  }
  matchesAccountDatabase(client: object): boolean {
    return client === this.store.consumerGuardReceiptIdentity;
  }
  requireReady() {
    if (!this.accepted || !this.fence) fail('SOURCE_UNSUPPORTED');
    this.assertCurrent(this.fence);
  }
  async status() {
    const s = await this.read();
    return {
      ...structuredClone(s.value),
      leaseCurrent: !this.closed && this.clock() < this.leaseUntil,
    };
  }
}
