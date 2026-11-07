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
>;
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
  state: 'QUIESCING' | 'READY' | 'UNKNOWN';
};
const drivers = new WeakSet<object>();
export function isManagedCoverageDriver(x: unknown): x is ManagedCoverageDriver {
  return !!x && typeof x === 'object' && drivers.has(x);
}
export class ManagedCoverageDriver implements ControlledCoverageDriver {
  readonly issuerId = randomUUID();
  readonly registration: CoverageRegistration;
  private readonly boot = randomUUID();
  private readonly profile: FixedCoverageProfile;
  private readonly profileHash: string;
  private readonly key = sha('publication-coverage-driver/v1');
  private closed = true;
  private fence?: string;
  private leaseUntil = 0;
  private epoch = 0;
  private lastClock = 0;
  private accepted?: ControlledCoverageReport;
  private readonly sourcePlan?: SourcePlanMetadata;
  private readonly sourceApproval?: () => void;
  private sourceBroker?: RestrictedPublicationCISourceBroker;
  private sourceReceipts?: { definition: object; ci?: object };
  private sourceCleanup?: Promise<void>;
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
    if (sourcePlan) {
      if (!/^[A-Za-z0-9_-]{1,100}$/.test(sourcePlan.operationId) || !sourcePlan.worker?.definition)
        fail('SOURCE_PLAN');
      const ci = sourcePlan.ci;
      if (ci && (!opaque(ci.instanceId) || !/^[a-f0-9]{40}$/.test(ci.head) ||
          !validHash(ci.workflowSha256) || typeof ci.assertDispatchApproved !== 'function'))
        fail('SOURCE_PLAN');
      this.sourcePlan = structuredClone({ operationId: sourcePlan.operationId, worker: sourcePlan.worker,
        ...(ci ? { ci: { instanceId: ci.instanceId, head: ci.head, workflowSha256: ci.workflowSha256 } } : {}) });
      this.sourceApproval = ci?.assertDispatchApproved;
    }
    this.registration = structuredClone(this.profile.registration);
    this.profileHash = this.expectedProfileHash();
    const r = this.registration;
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
    for (const x of this.profile.instances) {
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
        this.registration.instances.find((i) => i.instanceId === x.instanceId)!
          .entryDefinitionDigest !== coverageEntryDefinition(x.entryId, this.profile.source.files)
      )
        fail('ENTRY_DEFINITION');
    }
    if (this.sourcePlan?.ci) {
      const expected = this.profile.instances.find(x => x.instanceId === this.sourcePlan!.ci!.instanceId);
      if (!expected || expected.origin !== 'foreign-controller' || expected.entryId !== 'worksheet-ci' ||
          expected.state !== 'NATIVE_NAMESPACE_DENIED') fail('CI_SOURCE_PLAN');
    }
    drivers.add(this);
  }
  private expectedProfileHash() {
    return this.sourcePlan ? sha({ profile: this.profile, sourcePlan: this.sourcePlan }) : sha(this.profile);
  }
  private stopSource() {
    const broker = this.sourceBroker;
    this.sourceBroker = undefined;
    this.sourceReceipts = undefined;
    if (!broker) return;
    const previous = this.sourceCleanup;
    const closing = broker.revoke().finally(() => { this.lastSourceDiagnostics = broker.diagnostics(); });
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
  private async acquireSources(root: string, generation: string, epoch: number) {
    const plan = this.sourcePlan!;
    // A plan names the immutable tree we actually installed. It cannot substitute
    // the original checkout or a different interpreter for the loaded source.
    if (plan.worker.root !== root ||
        canonicalDigest(plan.worker.files) !== canonicalDigest(this.profile.source.files) ||
        canonicalDigest(plan.worker.python) !== canonicalDigest(this.profile.source.python))
      fail('SOURCE_RELEASE_BINDING');
    const lifecycle = await this.controller.produceLifecycle('LOADED');
    const fact = readManagedLifecycleReceipt(lifecycle, this.controller);
    if (fact.operationId !== plan.operationId || fact.root !== root ||
        fact.binding.generation !== generation || fact.binding.accountId !== this.accountScopeRef ||
        fact.binding.deviceId !== this.registration.deviceScopeRef || fact.ownedJobs !== 0 ||
        fact.unresolvedAdmissions !== 0 || fact.unknownNativeEffects !== 0) fail('SOURCE_LIFECYCLE');
    const broker = await RestrictedPublicationCISourceBroker.startOwned(
      this.store, this.plugin, plan.operationId, plan.worker, fact.binding,
      () => {
        this.ownerCurrent();
        if (epoch !== this.epoch) fail('REVOKED');
        return readManagedLifecycleReceipt(lifecycle, this.controller).binding;
      },
    );
    if (epoch !== this.epoch) {
      await broker.revoke();
      this.lastSourceDiagnostics = broker.diagnostics();
      fail('REVOKED');
    }
    this.sourceBroker = broker;
    broker.attachOwnedLifecycle(lifecycle, this.controller);
    // Missing original census/member/namespace owners closes before any dispatch.
    const handle = await broker.inspectDefinition();
    const definition = readPublicationSourceReceipt(handle, broker);
    this.validateDefinition(definition, fact, generation);
    this.sourceReceipts = { definition: handle };
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
    await broker.dispatchOriginalCI(plan.ci.head, plan.ci.workflowSha256, this.sourceApproval!);
    const handle = await broker.inspectCI();
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
  async quiesce() {
    this.close();
    // Both local owners revoke synchronously before either durable cleanup waits.
    const results = await Promise.allSettled([this.drainSource(), this.controller.revoke()]);
    const failure = results.find(x => x.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
    await this.controller.drain();
    const observed = await this.controller.coverageSourceState();
    if (observed.ownedJobs !== 0 || observed.unresolved !== 0) fail('UNRESOLVED');
    if ((await this.store.unknownNativePublicationEffects(this.plugin)) !== 0)
      fail('NATIVE_EFFECT_UNKNOWN');
  }
  async switchRelease(
    generation: string,
    previousSequence: number,
  ): Promise<ControlledCoverageReport> {
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
    if ((await this.store.unknownNativePublicationEffects(this.plugin)) !== 0)
      fail('NATIVE_EFFECT_UNKNOWN');
    const pending: DriverState = {
      ...old.value,
      boot: this.boot,
      state: 'QUIESCING',
      usedGenerations: [...old.value.usedGenerations, generation],
    };
    await this.save(old, pending);
    try {
      const release = await this.controller.install(this.profile.source, generation, this.sourcePlan?.operationId);
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
      const current = await this.read();
      await this.save(current, {
        ...pending,
        state: 'READY',
        releaseSequence: report.releaseSequence,
        lifecycleSequence: report.lifecycleSequence,
        lastVerified: report,
      });
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
          if (closedEpoch === this.epoch)
            await this.save(current, { ...current.value, state: 'UNKNOWN' });
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
      await this.controller.verifyCurrent(this.activeRoot!);
      if (epoch !== this.epoch) fail('REVOKED');
      if (this.sourcePlan) {
        if (!broker || !receipts) fail('SOURCE_CLOSED');
        // B owns a single sequenced channel. Each original private handle must
        // remain current; copied summary JSON cannot renew either source lease.
        await broker.current(receipts.definition);
        if (epoch !== this.epoch) fail('REVOKED');
        if (receipts.ci) await broker.current(receipts.ci);
      }
      const persisted = await this.read();
      if (epoch !== this.epoch || persisted.value.state !== 'READY' ||
          sha(persisted.value.lastVerified) !== sha(this.accepted)) fail('FACTS_CHANGED');
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
