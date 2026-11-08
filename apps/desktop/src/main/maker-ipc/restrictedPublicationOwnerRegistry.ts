/** Original-owner journal and C-source projection. No JSON fact importer.
 * Every current member is bound to an actual Main controller or authenticated
 * original process; every old member remains in the original account history.
 * Unrecorded legacy history and missing foreign owners are errors, not zeroes.
 */
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import { readPublicationHistoryReceipt } from './restrictedPartnerStore.js';
import { canonical, digest } from './restrictedPublicationProtocol.js';
import {
  isRestrictedPublicationCISourceBroker, readPublicationSourceReceipt,
  type RestrictedPublicationCISourceBroker, type PublicationSourceBinding,
} from './restrictedPublicationCISourceBroker.js';
import {
  ManagedPublicationController, readManagedLifecycleReceipt, readManagedEnrollmentReceipt,
  type ManagedLifecycleObservation,
} from './restrictedPublicationManagedController.js';
import {
  RestrictedPublicationResidentSource, isOriginalPublicationSource, readOriginalPublicationPeerReceipt,
  type OriginalPublicationPeerObservation,
} from './restrictedPublicationResidentSource.js';

const MAX_INSTANCES = 64;
const MAX_SOURCES = 16;
const MAX_PAGES = 16;
const PAGE_SIZE = 8;
const NONPUBLISHER_PAGE_SIZE = 4;
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const opaque = (v: unknown): v is string => typeof v === 'string' && v.length > 0 &&
  Buffer.byteLength(v) <= 512 && !/[\u0000-\u001f\u007f-\u009f]/.test(v);
function fail(code: string): never { throw Error('PUBLICATION_OWNER_REGISTRY_' + code); }
type Store = Pick<ReturnType<typeof createRestrictedPartnerStore>, 'consumerGuardReceiptIdentity' |
  'capturePublicationOwnerHistory' | 'assertPublicationOwnerHistoryCurrent' |
  'readConsumerGuardReceipt' | 'compareAndSwapConsumerGuardReceipt' |
  'unresolvedConsumerGuardAdmissions' | 'unknownNativePublicationEffects'>;
type Source = { sourceId: string; authorityId: string; kind: 'managed' | 'resident' | 'legacy' | 'namespace' };
type Member = { instanceId: string; entryId: string; profileId: string; definitionDigest: string;
  state: 'GUARDED' | 'NATIVE_NAMESPACE_DENIED' | 'RETIRED_FENCED'; censusSourceId: string; serviceLabel?: string };
type Namespace = { entryId: string; definitionDigest: string; censusSourceId: string;
  sourceProfileId: string; sourceIdentity: string; sourceRoot: string; sourceDigest: string;
  sourceFiles: Record<string, string>; origin: 'owned-controller' | 'foreign-controller' };
type NonPublisher = { serviceLabel: string; definitionDigest: string; sourceProfileId: string; censusSourceId: string };
type NonPublisherSource = Omit<Namespace, 'entryId' | 'definitionDigest'>;
export interface OriginalPublicationRegistryProfile {
  schema: 'publication-definition-profile/v1';
  sourceIdentity: string;
  sourceRoot: string;
  sourceDigest: string;
  sourceFiles: Record<string, string>;
  python: { path: string; sha256: string };
  censusSources: Source[];
  instances: Member[];
  namespaces: Namespace[];
  residentNonPublishers: NonPublisher[];
  residentNonPublisherSources: NonPublisherSource[];
  residentSource: { domain: string; executable: string; executableSha256: string };
}
type StoredMember = Member & { generation: string; sourceId: string; authorityId: string;
  evidenceKind: 'managed' | 'original-peer' | 'ci'; originalReceiptId: string;
  processIdentity?: string; peerId?: string; sourceOperationId?: string;
  loadedNonce?: string; retirementReceiptId?: string; disableReceiptId?: string; drainReceiptId?: string;
  ciIdentity?: { workflowId: number; runId: number; attempt: number; jobId: number;
    checkRunId: number; head: string; workflowSha256: string; operationNonce: string } };
type Ledger = { schema: 'publication-original-owner-registry/v1'; operationId: string;
  binding: PublicationSourceBinding; profileSha256: string;
  state: 'ENROLLING' | 'SEALED' | 'RETIRING' | 'RETIRED' | 'UNKNOWN' | 'REVOKED';
  members: StoredMember[]; namespaceIds: string[]; nonPublisherLabels: string[] };
type Row = Awaited<ReturnType<Store['readConsumerGuardReceipt']>>;
type HeldPeer = { source: RestrictedPublicationResidentSource; handle: object; value: OriginalPublicationPeerObservation };
const registries = new WeakSet<object>();
const seals = new WeakMap<object, { registry: RestrictedPublicationOwnerRegistry; revision: number; ci: boolean }>();
const retirements = new WeakMap<object, { registry: RestrictedPublicationOwnerRegistry;
  row: NonNullable<Row>; consumed: boolean;
  cutovers?: Array<{ source: RestrictedPublicationResidentSource; handle: object }> }>();
const completedRetirements = new WeakMap<object, { registry: RestrictedPublicationOwnerRegistry;
  controller: ManagedPublicationController; drainedHandle: object;
  sources: Set<RestrictedPublicationResidentSource>; verifyRecord: () => Promise<{ receiptId: string }>;
  verify: () => Promise<{ receiptId: string }> }>();
/** A completed original registry plus the actual Controller DRAINED handle.
 * Old LOADED handles cannot be used after revoke; JSON cannot reconstruct this. */
export async function verifyOriginalRetirementReceipt(handle: object, registry: RestrictedPublicationOwnerRegistry,
  source: RestrictedPublicationResidentSource, controller: ManagedPublicationController, drainedHandle: object) {
  const retained = completedRetirements.get(handle);
  if (!retained || retained.registry !== registry || !registries.has(registry) ||
      retained.controller !== controller || retained.drainedHandle !== drainedHandle ||
      !retained.sources.has(source) || !isOriginalPublicationSource(source)) fail('PRIVATE_RETIREMENT_REQUIRED');
  return retained.verify();
}
export function isOriginalPublicationRegistry(value: unknown): value is RestrictedPublicationOwnerRegistry {
  return !!value && typeof value === 'object' && registries.has(value);
}
export function readOriginalPublicationRegistrySeal(handle: object, registry: RestrictedPublicationOwnerRegistry) {
  const value = seals.get(handle);
  if (!value || value.registry !== registry || !registries.has(registry)) fail('PRIVATE_SEAL_REQUIRED');
  registry.assertRevision(value.revision);
  return { nonCIComplete: true as const, ciComplete: value.ci };
}

export class RestrictedPublicationOwnerRegistry {
  private readonly profile: OriginalPublicationRegistryProfile;
  private readonly lifecycle: Readonly<ManagedLifecycleObservation>;
  private readonly key: string;
  private ledger: Ledger;
  private row: Row;
  private history?: object;
  private historical: StoredMember[] = [];
  private readonly peers = new Map<string, HeldPeer>();
  private readonly managed = new Map<string, object>();
  private readonly namespacePeers = new Map<string, HeldPeer>();
  private readonly nonPublisherPeers = new Map<string, HeldPeer>();
  private readonly pages = new Map<string, Record<string, any>[]>();
  private readonly censusReceiptIds: string[] = [];
  private readonly issued = new Set<string>();
  private residentSnapshot?: string;
  private currentDigest?: string;
  private currentReceiptIds?: string[];
  private closed = false;
  private busy = false;
  private unsubscribe?: () => void;
  private retirementPrepared = false;
  private ciBinding?: { broker: RestrictedPublicationCISourceBroker; ci: object; inventoryHandle: object;
    value: Record<string, any>; inventory: Record<string, any> };
  private constructor(private readonly store: Store, private readonly plugin: string,
    readonly operationId: string, profile: OriginalPublicationRegistryProfile,
    private readonly controller: ManagedPublicationController, private readonly lifecycleHandle: object) {
    if (!(controller instanceof ManagedPublicationController) || !opaque(plugin) || !opaque(operationId)) fail('OWNER');
    this.lifecycle = readManagedLifecycleReceipt(lifecycleHandle, controller);
    if (this.lifecycle.phase !== 'LOADED' || this.lifecycle.operationId !== operationId) fail('LIFECYCLE');
    this.profile = structuredClone(profile);
    const p = this.profile;
    if (p.schema !== 'publication-definition-profile/v1' || !hex(p.sourceIdentity) ||
        p.sourceRoot !== this.lifecycle.root || p.sourceDigest !== this.lifecycle.sourceDigest ||
        canonical(p.sourceFiles) !== canonical(this.lifecycle.files) ||
        !Array.isArray(p.censusSources) || p.censusSources.length < 4 || p.censusSources.length > MAX_SOURCES ||
        new Set(p.censusSources.map(x => x.sourceId)).size !== p.censusSources.length ||
        p.censusSources.some(x => !opaque(x.sourceId) || !opaque(x.authorityId) ||
          !['managed', 'resident', 'legacy', 'namespace'].includes(x.kind)) ||
        !Array.isArray(p.instances) || !p.instances.length || p.instances.length > MAX_INSTANCES ||
        new Set(p.instances.map(x => x.instanceId)).size !== p.instances.length ||
        !Array.isArray(p.namespaces) || p.namespaces.length !== 4 ||
        !Array.isArray(p.residentNonPublishers) || !Array.isArray(p.residentNonPublisherSources)) fail('PROFILE');
    for (const member of p.instances) {
      if (!opaque(member.instanceId) || !hex(member.definitionDigest) || !opaque(member.entryId) ||
          !opaque(member.profileId) || !p.censusSources.some(x => x.sourceId === member.censusSourceId && x.kind !== 'namespace'))
        fail('PROFILE');
    }
    this.key = digest(['publication-original-owner-registry/v1', this.lifecycle.binding.deviceId, operationId]);
    this.ledger = { schema: 'publication-original-owner-registry/v1', operationId,
      binding: structuredClone(this.lifecycle.binding), profileSha256: digest(p), state: 'ENROLLING',
      members: [], namespaceIds: [], nonPublisherLabels: [] };
    registries.add(this);
    this.unsubscribe = controller.onSourceInvalidated(() => { void this.revoke(); });
  }
  static async startOwned(store: Store, plugin: string, operationId: string,
    profile: OriginalPublicationRegistryProfile, controller: ManagedPublicationController, lifecycleHandle: object) {
    const self = new RestrictedPublicationOwnerRegistry(store, plugin, operationId, profile, controller, lifecycleHandle);
    self.assertCurrent();
    if (await store.readConsumerGuardReceipt(plugin, self.lifecycle.binding.accountId, self.key) ||
        !await store.compareAndSwapConsumerGuardReceipt(plugin, self.lifecycle.binding.accountId, self.key,
          undefined, canonical(self.ledger))) fail('OPERATION_ALREADY_CLAIMED');
    self.row = await store.readConsumerGuardReceipt(plugin, self.lifecycle.binding.accountId, self.key);
    if (!self.row || self.row.revision !== 1 || self.row.payload !== canonical(self.ledger)) fail('LEDGER_CHANGED');
    return self;
  }
  assertCurrent() {
    if (this.closed) fail('CLOSED');
    const value = readManagedLifecycleReceipt(this.lifecycleHandle, this.controller);
    if (canonical(value.binding) !== canonical(this.lifecycle.binding) || value.operationId !== this.operationId)
      fail('BINDING');
  }
  assertRevision(revision: number) {
    this.assertCurrent();
    if (!this.row || this.row.revision !== revision || !['ENROLLING', 'SEALED'].includes(this.ledger.state)) fail('STALE_SEAL');
  }
  binding() { this.assertCurrent(); return structuredClone(this.lifecycle.binding); }
  profileSha256() { return digest(this.profile); }
  private expectedMember(instanceId: string) {
    const member = this.profile.instances.find(x => x.instanceId === instanceId);
    if (!member || this.ledger.members.some(x => x.instanceId === instanceId)) fail('MEMBER_REPLAY');
    return member;
  }
  private source(sourceId: string) {
    const source = this.profile.censusSources.find(x => x.sourceId === sourceId);
    if (!source) fail('SOURCE_REQUIRED');
    return source;
  }
  private async save(drained = false) {
    this.assertCurrent();
    const account = this.lifecycle.binding.accountId;
    const history = await this.store.capturePublicationOwnerHistory(this.plugin, account);
    if (!this.row || !await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, account, this.key,
        this.row, canonical(this.ledger), drained, history)) fail('LEDGER_CHANGED');
    const next = { revision: this.row.revision + 1, payload: canonical(this.ledger) };
    const actual = await this.store.readConsumerGuardReceipt(this.plugin, account, this.key);
    if (!actual || canonical(actual) !== canonical(next)) fail('LEDGER_CHANGED');
    this.row = actual;
    this.history = undefined;
    this.assertCurrent();
  }
  async bindManaged(instanceId: string, handle: object) {
    this.assertCurrent();
    const member = this.expectedMember(instanceId);
    const source = this.source(member.censusSourceId);
    if (source.kind !== 'managed' || member.state === 'RETIRED_FENCED' || member.entryId === 'worksheet-ci') fail('ORIGINAL_SOURCE_REQUIRED');
    const value = readManagedEnrollmentReceipt(handle, this.controller);
    if (value.entryId !== member.entryId || value.root !== this.profile.sourceRoot ||
        value.sourceDigest !== this.profile.sourceDigest || value.generation !== this.lifecycle.binding.generation ||
        value.nativeWithoutMain !== 'DENIED') fail('MANAGED_SOURCE');
    this.managed.set(instanceId, handle);
    this.ledger.members.push({ ...member, generation: value.generation, sourceId: source.sourceId,
      authorityId: source.authorityId, evidenceKind: 'managed', loadedNonce: value.nonce,
      originalReceiptId: digest(['managed-enrollment', value]) });
    await this.save();
  }
  async bindOriginal(instanceId: string, source: RestrictedPublicationResidentSource, handle: object) {
    this.assertCurrent();
    if (!isOriginalPublicationSource(source) || canonical(source.binding()) !== canonical(this.lifecycle.binding))
      fail('ORIGINAL_SOURCE_REQUIRED');
    const member = this.expectedMember(instanceId);
    const census = this.source(member.censusSourceId);
    const value = readOriginalPublicationPeerReceipt(handle, source);
    if (value.instanceId !== instanceId || value.ownerId !== member.profileId ||
        value.sourceScope !== 'RESIDENT_ORIGINAL_ENTRY' || value.definitionDigest !== member.definitionDigest ||
        value.root !== this.profile.sourceRoot || value.sourceDigest !== this.profile.sourceDigest ||
        canonical(value.files) !== canonical(this.profile.sourceFiles) || member.entryId === 'worksheet-ci' ||
        !['resident', 'legacy', 'managed'].includes(census.kind)) fail('MEMBER_SOURCE');
    const retired = member.state === 'RETIRED_FENCED';
    if (value.observation.state !== (retired ? 'RETIRED' : 'LOADED') ||
        value.observation.nativeWithoutMain !== 'DENIED' || value.observation.activeOperations !== 0 ||
        value.observation.unknownOperations !== 0 || !hex(value.observation.loadedNonce)) fail('MEMBER_STATE');
    this.peers.set(instanceId, { source, handle, value });
    const originalReceiptId = digest(['original-peer', source.operationId, value]);
    this.ledger.members.push({ ...member, generation: this.lifecycle.binding.generation,
      sourceId: census.sourceId, authorityId: census.authorityId, evidenceKind: 'original-peer',
      originalReceiptId, processIdentity: digest(value.process), peerId: value.peerId,
      sourceOperationId: source.operationId, loadedNonce: value.observation.loadedNonce,
      ...(retired ? { retirementReceiptId: digest(['retirement', originalReceiptId]),
        disableReceiptId: digest(['disable', originalReceiptId]), drainReceiptId: digest(['drain', originalReceiptId]) } : {}) });
    await this.save(retired);
  }
  async bindNamespace(entryId: string, source: RestrictedPublicationResidentSource, handle: object) {
    this.assertCurrent();
    const expected = this.profile.namespaces.find(x => x.entryId === entryId);
    if (!expected || this.namespacePeers.has(entryId) || !isOriginalPublicationSource(source) ||
        canonical(source.binding()) !== canonical(this.lifecycle.binding)) fail('NAMESPACE_SOURCE_REQUIRED');
    const value = readOriginalPublicationPeerReceipt(handle, source);
    if (value.sourceScope !== 'REGISTERED_NAMESPACE_OWNER' || value.ownerId !== entryId ||
        value.root !== expected.sourceRoot || value.sourceDigest !== expected.sourceDigest ||
        value.definitionDigest !== expected.definitionDigest || canonical(value.files) !== canonical(expected.sourceFiles) ||
        !['FENCED', 'DRAINED'].includes(value.observation.state) || value.observation.fenceRevision < 1 ||
        value.observation.activeOperations !== 0 || value.observation.unknownOperations !== 0 ||
        (expected.origin === 'foreign-controller' && value.root === this.profile.sourceRoot)) fail('NAMESPACE_SOURCE');
    this.namespacePeers.set(entryId, { source, handle, value });
    this.ledger.namespaceIds.push(entryId);
    await this.save();
  }
  async bindNonPublisher(serviceLabel: string, source: RestrictedPublicationResidentSource, handle: object) {
    this.assertCurrent();
    const expected = this.profile.residentNonPublishers.find(x => x.serviceLabel === serviceLabel);
    const provider = expected && this.profile.residentNonPublisherSources.find(x => x.sourceProfileId === expected.sourceProfileId);
    if (!expected || !provider || this.nonPublisherPeers.has(serviceLabel) || !isOriginalPublicationSource(source) ||
        canonical(source.binding()) !== canonical(this.lifecycle.binding))
      fail('NONPUBLISHER_ORIGINAL_SOURCE_REQUIRED');
    const value = readOriginalPublicationPeerReceipt(handle, source);
    if (value.ownerId !== serviceLabel || value.sourceScope !== 'REGISTERED_RESIDENT_NONPUBLISHER' ||
        value.definitionDigest !== expected.definitionDigest || value.root !== provider.sourceRoot ||
        value.sourceDigest !== provider.sourceDigest || canonical(value.files) !== canonical(provider.sourceFiles) ||
        !['FENCED', 'DRAINED'].includes(value.observation.state) || value.observation.fenceRevision < 1 ||
        value.observation.activeOperations !== 0 || value.observation.unknownOperations !== 0) fail('NONPUBLISHER_SOURCE');
    this.nonPublisherPeers.set(serviceLabel, { source, handle, value });
    this.ledger.nonPublisherLabels.push(serviceLabel);
    await this.save();
  }
  /** Called only by the held broker after its private original B and inventory
   * handles have been verified. Not exported as a JSON registration entry. */
  async bindCIFromBroker(instanceId: string, broker: RestrictedPublicationCISourceBroker,
    ci: object, inventoryHandle: object): Promise<void> {
    this.assertCurrent();
    if (!isRestrictedPublicationCISourceBroker(broker) || broker.operationId !== this.operationId || this.ciBinding)
      fail('CI_ORIGINAL_SOURCE_REQUIRED');
    const member = this.expectedMember(instanceId);
    const source = this.source(member.censusSourceId);
    if (member.entryId !== 'worksheet-ci' || member.state !== 'NATIVE_NAMESPACE_DENIED' || source.kind !== 'managed')
      fail('CI_MEMBER_PROFILE');
    const value = readPublicationSourceReceipt(ci, broker);
    const inventory = readPublicationSourceReceipt(inventoryHandle, broker);
    const dispatch = broker.originalDispatchBinding();
    const binding = this.lifecycle.binding;
    const tuple = [binding.accountId, binding.deviceId, binding.bootId, binding.ownerEpoch, binding.generation];
    if (value.schema !== 'core-worksheet-owner-observation/v1' || value.operation_id !== this.operationId ||
        value.state !== 'NATIVE_NAMESPACE_DENIED' || value.consumer !== 'worksheet-ci' ||
        canonical(value.owner_binding) !== canonical(tuple) || value.head_sha !== dispatch.head ||
        value.workflow_sha256 !== dispatch.workflowSha256 ||
        inventory.schema !== 'publication-ci-inventory-source/v1' || inventory.operation_id !== this.operationId ||
        canonical(inventory.owner_binding) !== canonical(tuple) || inventory.history_complete !== true ||
        inventory.scope !== 'REGISTERED_WORKFLOW_HISTORY_ONLY' || !Array.isArray(inventory.members) ||
        inventory.anchor?.run_id !== value.run_id || inventory.anchor?.attempt !== value.attempt ||
        inventory.anchor?.job_id !== value.job_id || inventory.anchor?.check_run_id !== value.check_run_id ||
        !Number.isSafeInteger(inventory.workflow?.id) || inventory.workflow.id < 1) fail('CI_SOURCE_BINDING');
    await this.captureHistory();
    let anchor = false;
    for (const item of inventory.members) {
      const denial = item.native_denial;
      const isAnchor = item.run_id === value.run_id && item.attempt === value.attempt && item.job_id === value.job_id;
      if (isAnchor) {
        if (anchor || denial?.original_main_binding_state !== 'BOUND' || denial.operation_nonce !== dispatch.operationNonce ||
            denial.original_operation_id !== this.operationId || canonical(denial.original_owner_binding) !== canonical(tuple))
          fail('CI_ANCHOR_BINDING');
        anchor = true;
      } else {
        const excluded = item.branch_nonexecution;
        if (excluded?.schema === 'publication-ci-branch-nonexecution/v1' && excluded.state === 'BRANCH_EXCLUDED' &&
            excluded.run_id === item.run_id && excluded.attempt === item.attempt && excluded.job_id === item.job_id &&
            excluded.job_key === 'publish' && excluded.workflow_sha256 === item.workflow_sha256 &&
            excluded.head_sha === item.head_sha && hex(excluded.guard_notice_sha256) &&
            opaque(excluded.original_operation_id) && Array.isArray(excluded.original_owner_binding)) continue;
        const old = this.historical.find(x => {
          const identity = x.ciIdentity;
          return x.evidenceKind === 'ci' && identity !== undefined && identity.workflowId === inventory.workflow.id &&
            identity.runId === item.run_id && identity.attempt === item.attempt && identity.jobId === item.job_id;
        });
        if (!old || old.state !== 'RETIRED_FENCED' || !old.retirementReceiptId || !old.disableReceiptId || !old.drainReceiptId ||
            denial?.original_main_binding_state !== 'BOUND' || old.ciIdentity!.checkRunId !== item.check_run_id ||
            old.ciIdentity!.head !== item.head_sha || old.ciIdentity!.workflowSha256 !== item.workflow_sha256 ||
            old.ciIdentity!.operationNonce !== denial.operation_nonce) fail('CI_HISTORICAL_DISPOSITION_REQUIRED');
      }
    }
    if (!anchor || this.historical.some(x => x.evidenceKind === 'ci' && x.ciIdentity?.workflowId !== inventory.workflow.id))
      fail('CI_WORKFLOW_ORIGINAL_HISTORY_REQUIRED');
    // This source deliberately cannot prove a deleted/recreated workflow did
    // not exist. There is no original creation/retirement journal in the
    // recovered inputs. A current API list, empty local DB or approval cannot
    // supply that missing authority. Preserve its explicit limited scope.
    // No original workflow-creation/retirement owner source was recovered. Do
    // not invent an unlock boolean in this limited-scope inventory contract.
    this.requireOriginalWorkflowHistory(inventory);
    this.ciBinding = { broker, ci, inventoryHandle, value, inventory };
    this.ledger.members.push({ ...member, generation: binding.generation, sourceId: source.sourceId,
      authorityId: source.authorityId, evidenceKind: 'ci', loadedNonce: dispatch.operationNonce,
      originalReceiptId: digest(['original-ci', value, inventory.snapshot_sha256]),
      ciIdentity: { workflowId: inventory.workflow.id, runId: value.run_id, attempt: value.attempt,
        jobId: value.job_id, checkRunId: value.check_run_id, head: dispatch.head,
        workflowSha256: dispatch.workflowSha256, operationNonce: dispatch.operationNonce } });
    await this.save();
  }
  private requireOriginalWorkflowHistory(_inventory: Record<string, any>): void {
    // Deliberate integration boundary: must be replaced only by a concrete
    // original private owner producer, never a profile flag or JSON receipt.
    fail('CI_WORKFLOW_ORIGINAL_HISTORY_REQUIRED');
  }
  private async captureHistory() {
    const account = this.lifecycle.binding.accountId;
    const handle = await this.store.capturePublicationOwnerHistory(this.plugin, account);
    const facts = readPublicationHistoryReceipt(handle, this.store.consumerGuardReceiptIdentity, this.plugin, account);
    const old: StoredMember[] = [];
    const seen = new Set(this.ledger.members.map(x => x.instanceId));
    for (const row of facts.rows) {
      const value = JSON.parse(row.payload) as Record<string, any>;
      if (value.schema === 'publication-main-source-operation/v1' && value.operationId !== this.operationId &&
          (value.state === 'DISPATCHING_UNKNOWN' ||
            (value.runId !== null && (!value.dispatchBinding || !value.verifiedCI)))) fail('CI_ORIGINAL_HISTORY_REQUIRED');
      if (value.schema !== 'publication-original-owner-registry/v1' || value.operationId === this.operationId) continue;
      if (!['RETIRED', 'REVOKED', 'SEALED'].includes(value.state) || !value.binding || value.binding.accountId !== account ||
          value.binding.deviceId !== this.lifecycle.binding.deviceId || !Array.isArray(value.members)) fail('HISTORY_UNKNOWN');
      for (const member of value.members as StoredMember[]) {
        if (!opaque(member.instanceId) || !opaque(member.generation) || member.generation === this.lifecycle.binding.generation ||
            seen.has(member.instanceId) || !hex(member.definitionDigest) || !opaque(member.originalReceiptId) ||
            member.state !== 'RETIRED_FENCED' || !opaque(member.retirementReceiptId) ||
            !opaque(member.disableReceiptId) || !opaque(member.drainReceiptId)) fail('HISTORY_UNRETIRED');
        const source = this.source(member.sourceId);
        if (source.authorityId !== member.authorityId || source.sourceId !== member.censusSourceId) fail('HISTORY_SOURCE');
        seen.add(member.instanceId); old.push(structuredClone(member));
        if (seen.size > MAX_INSTANCES) fail('HISTORY_LIMIT');
      }
    }
    // Old Main generations are original source facts. An absent new registry
    // row does not erase them or turn an old install into a retired instance.
    const original = await this.controller.coverageSourceState();
    for (const generation of original.state.usedGenerations) {
      if (generation !== this.lifecycle.binding.generation && !old.some(x => x.generation === generation))
        fail('LEGACY_MEMBERSHIP_UNRECORDED');
    }
    for (const source of this.profile.censusSources) {
      if (source.kind === 'legacy' && !this.ledger.members.some(x => x.sourceId === source.sourceId) &&
          !old.some(x => x.sourceId === source.sourceId)) fail('LEGACY_ORIGINAL_HISTORY_REQUIRED');
    }
    await this.store.assertPublicationOwnerHistoryCurrent(handle, this.plugin, account);
    this.history = handle;
    this.historical = old;
  }
  private async verifyActualSources() {
    await this.controller.verifyLifecycleReceipt(this.lifecycleHandle);
    for (const [instanceId, handle] of this.managed) {
      const value = readManagedEnrollmentReceipt(handle, this.controller);
      if (value.generation !== this.lifecycle.binding.generation || value.entryId !== this.ledger.members.find(x => x.instanceId === instanceId)?.entryId)
        fail('MANAGED_SOURCE_CHANGED');
    }
    for (const held of [...this.peers.values(), ...this.namespacePeers.values(), ...this.nonPublisherPeers.values()]) {
      const current = await held.source.current(held.handle);
      const value = readOriginalPublicationPeerReceipt(current, held.source);
      if (digest({ ...value, observation: { ...value.observation, probe: null } }) !==
          digest({ ...held.value, observation: { ...held.value.observation, probe: null } })) fail('ORIGINAL_SOURCE_CHANGED');
      held.handle = current;
    }
    if (this.ciBinding) {
      // The broker surrounds the complete C read with asynchronous B/inventory
      // freshness. Reentering its worker inside a C callback would deadlock.
      const held = this.ciBinding;
      if (canonical(readPublicationSourceReceipt(held.ci, held.broker)) !== canonical(held.value) ||
          canonical(readPublicationSourceReceipt(held.inventoryHandle, held.broker)) !== canonical(held.inventory))
        fail('CI_SOURCE_CHANGED');
    }
    this.assertCurrent();
  }
  /** Close only genuinely held original invocations. Main must first close its
   * business admission lease. No process is declared retired from OS absence,
   * a terminal GitHub status, or a requested profile disposition. */
  async prepareRetirement() {
    this.assertCurrent();
    if (this.busy || this.retirementPrepared || this.ciBinding) fail('RETIREMENT_ORIGINAL_SOURCE_REQUIRED');
    this.busy = true;
    try {
      this.ledger.state = 'RETIRING';
      await this.save();
      for (const held of [...this.peers.values(), ...this.namespacePeers.values(), ...this.nonPublisherPeers.values()]) {
        let handle = held.handle;
        let observed = readOriginalPublicationPeerReceipt(handle, held.source);
        for (const [phase, method] of [['LOADED', 'fence'], ['FENCED', 'drain'], ['DRAINED', 'retire']] as const) {
          if (observed.observation.state === phase) {
            handle = await held.source.transition(handle, method);
            observed = readOriginalPublicationPeerReceipt(handle, held.source);
          }
        }
        if (observed.observation.state !== 'RETIRED' || observed.observation.activeOperations !== 0 ||
            observed.observation.unknownOperations !== 0 || observed.observation.fenceRevision < 1)
          fail('RETIREMENT_UNKNOWN');
        held.handle = handle; held.value = observed;
        const member = this.ledger.members.find(x => x.instanceId === observed.instanceId);
        if (member) {
          if (member.evidenceKind !== 'original-peer' || member.peerId !== observed.peerId ||
              member.processIdentity !== digest(observed.process)) fail('RETIREMENT_BINDING');
          member.state = 'RETIRED_FENCED';
          member.retirementReceiptId = digest(['original-retired-peer', held.source.operationId, observed]);
          member.disableReceiptId = digest(['original-peer-fence', member.originalReceiptId, observed.observation.fenceRevision]);
          member.drainReceiptId = digest(['original-peer-drain', member.retirementReceiptId]);
        }
        await this.save(true);
      }
      const handle = Object.freeze(Object.create(null)) as object;
      this.retirementPrepared = true;
      this.unsubscribe?.(); this.unsubscribe = undefined;
      retirements.set(handle, { registry: this, row: structuredClone(this.row!), consumed: false });
      return handle;
    } finally { this.busy = false; }
  }
  /** Called only for a planned generation switch. Ordinary invalidation does
   * not retain listeners, and no future business admission is retained. */
  async retainPolicyCutovers(prepared: object) {
    const retained = retirements.get(prepared);
    if (!retained || retained.registry !== this || retained.consumed || retained.cutovers ||
        !this.retirementPrepared) fail('PRIVATE_RETIREMENT_REQUIRED');
    this.assertCurrent();
    if (this.profile.instances.some(x => !this.ledger.members.some(y => y.instanceId === x.instanceId)) ||
        this.profile.namespaces.some(x => !this.namespacePeers.has(x.entryId)) ||
        this.profile.residentNonPublishers.some(x => !this.nonPublisherPeers.has(x.serviceLabel)))
      fail('RETIREMENT_ORIGINAL_SOURCE_REQUIRED');
    const sources = [...new Set([...this.peers.values(), ...this.namespacePeers.values(),
      ...this.nonPublisherPeers.values()].map(x => x.source))];
    const held: Array<{ source: RestrictedPublicationResidentSource; handle: object }> = [];
    for (const source of sources)
      held.push({ source, handle: await source.retainForPolicyCutover(this.controller, this.lifecycleHandle) });
    retained.cutovers = held;
    return held.slice();
  }
  /** The second half uses the original Controller's actual DRAINED transition
   * after its synchronous revoke. Old LOADED handles deliberately no longer
   * work here. The private preparation can be consumed only once. */
  async completeRetirement(prepared: object, drainedHandle: object) {
    const retained = retirements.get(prepared);
    if (!retained || retained.registry !== this || retained.consumed || !this.retirementPrepared) fail('PRIVATE_RETIREMENT_REQUIRED');
    retained.consumed = true;
    const actual = await this.controller.verifyLifecycleReceipt(drainedHandle);
    if (actual.phase !== 'DRAINED' || actual.operationId !== this.operationId ||
        actual.root !== this.lifecycle.root || actual.sourceDigest !== this.lifecycle.sourceDigest ||
        actual.binding.accountId !== this.lifecycle.binding.accountId || actual.binding.deviceId !== this.lifecycle.binding.deviceId ||
        actual.binding.bootId !== this.lifecycle.binding.bootId || actual.binding.generation !== this.lifecycle.binding.generation ||
        actual.binding.ownerEpoch <= this.lifecycle.binding.ownerEpoch || actual.ownedJobs !== 0 ||
        actual.unresolvedAdmissions !== 0 || actual.unknownNativeEffects !== 0) fail('RETIREMENT_DRAIN_BINDING');
    const next = structuredClone(this.ledger);
    for (const member of next.members) {
      if (member.state === 'RETIRED_FENCED') continue;
      if (member.evidenceKind !== 'managed' || !this.managed.has(member.instanceId)) fail('RETIREMENT_ORIGINAL_SOURCE_REQUIRED');
      member.state = 'RETIRED_FENCED';
      member.retirementReceiptId = digest(['original-managed-retirement', member.originalReceiptId, actual]);
      member.disableReceiptId = digest(['original-managed-disable', member.originalReceiptId, actual.binding.ownerEpoch]);
      member.drainReceiptId = digest(['original-managed-drain', member.originalReceiptId, actual]);
    }
    next.state = 'RETIRED';
    const history = await this.store.capturePublicationOwnerHistory(this.plugin, this.lifecycle.binding.accountId);
    if (canonical(await this.controller.verifyLifecycleReceipt(drainedHandle)) !== canonical(actual) ||
        canonical(await this.store.readConsumerGuardReceipt(this.plugin, this.lifecycle.binding.accountId, this.key)) !==
          canonical(retained.row)) fail('RETIREMENT_LEDGER_CHANGED');
    if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.lifecycle.binding.accountId,
        this.key, retained.row, canonical(next), true, history)) fail('RETIREMENT_LEDGER_CHANGED');
    await this.controller.verifyLifecycleReceipt(drainedHandle);
    this.row = { revision: retained.row.revision + 1, payload: canonical(next) };
    this.ledger = next; this.closed = true;
    const row = structuredClone(this.row);
    const sources = new Set([...this.peers.values(), ...this.namespacePeers.values(),
      ...this.nonPublisherPeers.values()].map(x => x.source));
    const receipt = Object.freeze(Object.create(null)) as object;
    const verifyRecord = async () => {
        if (!this.closed || this.ledger.state !== 'RETIRED' ||
            canonical(await this.store.readConsumerGuardReceipt(this.plugin, actual.binding.accountId, this.key)) !==
              canonical(row)) fail('RETIREMENT_LEDGER_CHANGED');
        return { receiptId: digest(['publication-original-completed-retirement/v1', this.key, row, actual]) };
    };
    completedRetirements.set(receipt, { registry: this, controller: this.controller, drainedHandle, sources, verifyRecord,
      verify: async () => {
        const current = await this.controller.verifyLifecycleReceipt(drainedHandle);
        if (canonical(current) !== canonical(actual)) fail('RETIREMENT_LEDGER_CHANGED');
        return verifyRecord();
      } });
    return receipt;
  }
  /** Retained original journal only; no new generation's lifecycle authority. */
  async verifyCompletedRetirementRecord(receipt: object) {
    const retained = completedRetirements.get(receipt);
    if (!retained || retained.registry !== this || !registries.has(this)) fail('PRIVATE_RETIREMENT_REQUIRED');
    return retained.verifyRecord();
  }
  /** Check next pinned C expectations against the original retired registry.
   * Old records remain historical; their source/authority mapping must survive
   * without reenrolling any consumed instance or changing its source kind. */
  async validateCutoverDefinition(receipt: object, drainedHandle: object, next: OriginalPublicationRegistryProfile) {
    const retained = completedRetirements.get(receipt);
    if (!retained || retained.registry !== this || retained.controller !== this.controller ||
        retained.drainedHandle !== drainedHandle) fail('PRIVATE_RETIREMENT_REQUIRED');
    await retained.verify();
    if (!next || next.schema !== 'publication-definition-profile/v1' || !Array.isArray(next.censusSources) ||
        !Array.isArray(next.instances) || next.censusSources.length > MAX_SOURCES || next.instances.length > MAX_INSTANCES ||
        this.profile.censusSources.some(old => !next.censusSources.some(value => canonical(value) === canonical(old))) ||
        new Set([...this.ledger.members, ...this.historical, ...next.instances].map(value => value.instanceId)).size > MAX_INSTANCES ||
        next.instances.some(value => [...this.ledger.members, ...this.historical].some(old => old.instanceId === value.instanceId)))
      fail('CUTOVER_DEFINITION_HISTORY');
    await retained.verify();
  }
  async preflightNonCI() {
    this.assertCurrent();
    const expected = this.profile.instances.filter(x => x.entryId !== 'worksheet-ci');
    if (expected.some(x => !this.ledger.members.some(y => y.instanceId === x.instanceId && y.state === x.state)) ||
        this.profile.namespaces.some(x => !this.namespacePeers.has(x.entryId)) ||
        this.profile.residentNonPublishers.some(x => !this.nonPublisherPeers.has(x.serviceLabel))) fail('ORIGINAL_SOURCES_INCOMPLETE');
    await this.verifyActualSources();
    await this.captureHistory();
    // The account journal is complete within its original SQL scope. It cannot
    // establish the universe of pre-journal/foreign legacy installations. No
    // authenticated historical cutover producer exists in the recovered input.
    // In particular, one known legacy row is not proof that all others are absent.
    if (this.profile.censusSources.some(x => x.kind === 'legacy')) fail('HISTORY_BOOTSTRAP_UNAVAILABLE');
    if (await this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.lifecycle.binding.accountId) !== 0 ||
        await this.store.unknownNativePublicationEffects(this.plugin) !== 0) fail('FENCE_UNRESOLVED');
    const seal = Object.freeze(Object.create(null)) as object;
    seals.set(seal, { registry: this, revision: this.row!.revision, ci: !!this.ciBinding });
    return seal;
  }
  async seal() {
    await this.preflightNonCI();
    if (this.profile.instances.some(x => !this.ledger.members.some(y => y.instanceId === x.instanceId))) fail('CI_ORIGINAL_HISTORY_REQUIRED');
    this.ledger.state = 'SEALED';
    await this.save(true);
    await this.captureHistory();
    const handle = Object.freeze(Object.create(null)) as object;
    seals.set(handle, { registry: this, revision: this.row!.revision, ci: true });
    return handle;
  }
  private base(schema: string) {
    return { schema, operationId: this.operationId, binding: structuredClone(this.lifecycle.binding) };
  }
  private issue(kind: string, subject: unknown) {
    const id = digest(['publication-original-source-receipt/v1', this.operationId, this.row!.revision, kind, subject]);
    this.issued.add(id);
    return id;
  }
  private async assertSealed() {
    this.assertCurrent();
    if (this.ledger.state !== 'SEALED' || !this.history) fail('CENSUS_NOT_SEALED');
    await this.store.assertPublicationOwnerHistoryCurrent(this.history, this.plugin, this.lifecycle.binding.accountId);
    await this.controller.verifyLifecycleReceipt(this.lifecycleHandle);
  }
  async query(method: string, args: Record<string, any>) {
    if (this.busy) fail('BUSY');
    this.busy = true;
    try {
      await this.assertSealed();
      let value: Record<string, any>;
      if (method === 'census') value = await this.census(args);
      else if (method === 'member') value = await this.member(args);
      else if (method === 'namespace') value = await this.namespace(args);
      else if (method === 'fence') value = await this.fence(args);
      else if (method === 'current') { await this.verifyActualSources(); value = this.current(args); }
      else fail('METHOD');
      await this.assertSealed();
      if (Buffer.byteLength(canonical(value)) > 65536) fail('FRAME_LIMIT');
      return value;
    } catch (error) { await this.revoke('UNKNOWN'); throw error; }
    finally { this.busy = false; }
  }
  private record(member: StoredMember) {
    return { instanceId: member.instanceId, entryId: member.entryId, definitionDigest: member.definitionDigest,
      generation: member.generation, state: member.state, ...(member.serviceLabel ? { serviceLabel: member.serviceLabel } : {}) };
  }
  private async census(args: Record<string, any>) {
    const source = this.source(args.sourceId);
    const resident = source.kind === 'resident';
    const wanted = resident ? ['sourceId', 'cursor', 'residentSnapshotSha256', 'challengeNonce'] : ['sourceId', 'cursor'];
    if (Object.keys(args).sort().join(',') !== wanted.sort().join(',') || !Number.isInteger(args.cursor) ||
        args.cursor < 0 || args.cursor >= MAX_PAGES ||
        (resident && (!hex(args.residentSnapshotSha256) || !hex(args.challengeNonce)))) fail('CENSUS_REQUEST');
    if (resident) {
      if (this.residentSnapshot && this.residentSnapshot !== args.residentSnapshotSha256) fail('RESIDENT_SNAPSHOT_CHANGED');
      this.residentSnapshot = args.residentSnapshotSha256;
    }
    let pages = this.pages.get(source.sourceId);
    if (!pages) { if (args.cursor !== 0) fail('CENSUS_GAP'); pages = []; this.pages.set(source.sourceId, pages); }
    if (args.cursor !== pages.length) fail('CENSUS_REPLAY');
    const all = [...this.ledger.members, ...this.historical].filter(x => x.sourceId === source.sourceId)
      .sort((a, b) => a.instanceId.localeCompare(b.instanceId));
    if (all.length > MAX_INSTANCES) fail('CENSUS_LIMIT');
    const nonPublishers = resident ? this.profile.residentNonPublishers.filter(x => x.censusSourceId === source.sourceId) : [];
    const pageCount = Math.max(1, Math.ceil(all.length / PAGE_SIZE), Math.ceil(nonPublishers.length / NONPUBLISHER_PAGE_SIZE));
    if (pageCount > MAX_PAGES || args.cursor >= pageCount) fail('CENSUS_LIMIT');
    const records = all.slice(args.cursor * PAGE_SIZE, (args.cursor + 1) * PAGE_SIZE).map(x => this.record(x));
    const receiptId = this.issue('census', { source, cursor: args.cursor, records });
    const value: Record<string, any> = { ...this.base('publication-owner-census/v1'), ...source,
      cursor: args.cursor, previousPageSha256: pages.length ? digest(pages[pages.length - 1]) : null,
      snapshotId: digest([this.row, source.sourceId]), revision: this.row!.revision, receiptId, records,
      nextCursor: args.cursor + 1 < pageCount ? args.cursor + 1 : null };
    if (resident) {
      value.residentSnapshotSha256 = args.residentSnapshotSha256;
      value.nonPublisherExclusions = await this.nonPublishers(source, receiptId, args);
    }
    pages.push(value); this.censusReceiptIds.push(receiptId);
    return value;
  }
  private async member(args: Record<string, any>) {
    const member = this.ledger.members.find(x => x.instanceId === args.instanceId);
    if (!member) fail('MEMBER_REQUEST');
    const source = this.source(member.sourceId);
    const resident = source.kind === 'resident';
    const keys = resident ? 'censusReceiptId,instanceId,residentSnapshotSha256' : 'censusReceiptId,instanceId';
    const page = this.pages.get(source.sourceId)?.find(x => x.receiptId === args.censusReceiptId);
    if (Object.keys(args).sort().join(',') !== keys ||
        !page?.records.some((x: Record<string, unknown>) => x.instanceId === member.instanceId &&
          canonical(x) === canonical(this.record(member)))) fail('MEMBER_REQUEST');
    if (resident && args.residentSnapshotSha256 !== this.residentSnapshot) fail('RESIDENT_SNAPSHOT_CHANGED');
    const original = this.peers.get(member.instanceId);
    if (original) {
      const current = await original.source.current(original.handle);
      const observed = readOriginalPublicationPeerReceipt(current, original.source);
      if (canonical({ ...observed, observation: { ...observed.observation, probe: null } }) !==
          canonical({ ...original.value, observation: { ...original.value.observation, probe: null } })) fail('ORIGINAL_SOURCE_CHANGED');
      original.handle = current;
    }
    const proof: Record<string, any> = {};
    if (member.state === 'GUARDED') {
      const held = this.peers.get(member.instanceId);
      const managed = this.managed.get(member.instanceId);
      if (!held && !managed) fail('LOADED_SOURCE_REQUIRED');
      Object.assign(proof, { kind: 'loaded-guard', root: this.profile.sourceRoot, sourceDigest: this.profile.sourceDigest,
        files: this.profile.sourceFiles, resolvedInterpreter: this.profile.python.path,
        entryScript: held?.value.entryScript ?? ({ 'canonical-producer': 'scripts/publish_html_report.py',
          'generic-direct': 'scripts/publish_generic_html_direct.py', 'shared-transaction': 'scripts/publish_worksheet_html.py' } as Record<string, string>)[member.profileId],
        nativeWithoutMain: 'DENIED', businessEffects: 0, nonce: member.loadedNonce,
        enrollmentReceiptId: this.issue('enrollment', member), loadedReceiptId: this.issue('loaded', member),
        entrySwitchReceiptId: this.issue('entry-switch', this.lifecycle),
        immutableInstallReceiptId: this.issue('immutable-install', this.lifecycle) });
      if (resident) {
        if (!held || held.value.sourceScope !== 'RESIDENT_ORIGINAL_ENTRY') fail('RESIDENT_ORIGINAL_SOURCE_REQUIRED');
        Object.assign(proof, { sourceScope: held.value.sourceScope, processId: held.value.process.processId,
          processStartIdentity: digest(held.value.process.startIdentity), residentSnapshotSha256: this.residentSnapshot,
          definitionLabel: member.serviceLabel, definitionArgv: undefined, definitionWorkingDirectory: held.value.process.cwd });
        // Original definition argv is held by the listener descriptor, not
        // reconstructed from a new child or supplied by C's request.
        const descriptor = held.source.originalDescriptor(member.instanceId);
        proof.definitionArgv = descriptor.originalArgv;
      }
    } else if (member.state === 'NATIVE_NAMESPACE_DENIED') {
      if (!this.peers.has(member.instanceId) && !this.managed.has(member.instanceId) &&
          !(member.entryId === 'worksheet-ci' && this.ciBinding)) fail('DENIAL_SOURCE_REQUIRED');
      Object.assign(proof, { kind: 'native-denial', nativeWithoutMain: 'DENIED', probeNonce: member.loadedNonce,
        denialReceiptId: this.issue('native-denial', member) });
    } else {
      if (!member.retirementReceiptId || !member.disableReceiptId || !member.drainReceiptId) fail('RETIREMENT_SOURCE_REQUIRED');
      Object.assign(proof, { kind: 'retired-fenced', retirementReceiptId: this.issue('retirement', member),
        disableReceiptId: this.issue('disable', member), drainReceiptId: this.issue('drain', member),
        fenceReceiptId: this.issue('fence', this.lifecycle.binding), unresolvedAdmissions: 0, unknownNativeEffects: 0 });
    }
    return { ...this.base('publication-owner-member/v1'), ...this.record(member), profileId: member.profileId,
      authorityId: source.authorityId, censusReceiptId: args.censusReceiptId, sourceIdentity: this.profile.sourceIdentity,
      fenceRevision: this.row!.revision, receiptId: this.issue('member', member), proof,
      ...(resident ? { residentSnapshotSha256: this.residentSnapshot } : {}) };
  }
  private async namespace(args: Record<string, any>) {
    if (Object.keys(args).sort().join(',') !== 'censusReceiptIds,challengeNonce,entryId' ||
        canonical(args.censusReceiptIds) !== canonical(this.censusReceiptIds) || !hex(args.challengeNonce)) fail('NAMESPACE_REQUEST');
    const expected = this.profile.namespaces.find(x => x.entryId === args.entryId);
    const held = expected && this.namespacePeers.get(expected.entryId);
    if (!expected || !held) fail('NAMESPACE_SOURCE_REQUIRED');
    const source = this.source(expected.censusSourceId);
    const probeHandle = await held.source.probe(held.handle, {
      nonce: args.challengeNonce, generation: this.lifecycle.binding.generation });
    const raw = readOriginalPublicationPeerReceipt(probeHandle, held.source).observation.probe;
    if (!raw || raw.schema !== 'publication-original-namespace-observation/v1' || raw.entryId !== expected.entryId ||
        raw.nonce !== args.challengeNonce || raw.generation !== this.lifecycle.binding.generation ||
        raw.nativeWithoutMain !== 'DENIED' || raw.businessEffects !== 0 || raw.sourceRoot !== expected.sourceRoot ||
        raw.processId !== held.value.process.processId) fail('NAMESPACE_PROBE');
    const pins = { sourceProfileId: expected.sourceProfileId, sourceIdentity: expected.sourceIdentity,
      sourceRoot: expected.sourceRoot, sourceDigest: expected.sourceDigest, sourceFiles: expected.sourceFiles, origin: expected.origin };
    const common = { entryId: expected.entryId, definitionDigest: expected.definitionDigest, ...pins,
      sourceId: source.sourceId, authorityId: source.authorityId, censusReceiptIds: this.censusReceiptIds,
      fenceRevision: held.value.observation.fenceRevision };
    const probeId = this.issue('namespace-probe', { common, nonce: args.challengeNonce, raw });
    return { ...this.base('publication-owner-namespace/v1'), ...common, receiptId: this.issue('namespace', common),
      proof: { kind: 'namespace-fence', nativeIntersection: 'DENIED', scope: 'REGISTERED_NAMESPACE_OWNER',
        ownerReceiptId: this.issue('namespace-owner', common), fenceReceiptId: this.issue('namespace-fence', common),
        sourceProbeReceiptId: probeId, sourceProbe: { ...this.base('publication-namespace-owner-probe/v1'),
          ...common, scope: 'REGISTERED_NAMESPACE_OWNER', receiptId: probeId, nativeWithoutMain: 'DENIED', nonce: args.challengeNonce },
        ...(expected.entryId === 'private-report-files' ? { privateTarget: raw.privateTarget, privateAcl: raw.privateAcl } : {}) } };
  }
  private async nonPublishers(source: Source, censusReceiptId: string, args: Record<string, any>) {
    const result = [];
    for (const expected of this.profile.residentNonPublishers.filter(x => x.censusSourceId === source.sourceId)
      .slice(args.cursor * NONPUBLISHER_PAGE_SIZE, (args.cursor + 1) * NONPUBLISHER_PAGE_SIZE)) {
      const held = this.nonPublisherPeers.get(expected.serviceLabel);
      const provider = this.profile.residentNonPublisherSources.find(x => x.sourceProfileId === expected.sourceProfileId);
      if (!held || !provider) fail('NONPUBLISHER_ORIGINAL_SOURCE_REQUIRED');
      const nonce = digest([args.challengeNonce, expected.serviceLabel]);
      const scope = digest({ sourceIdentity: this.profile.sourceIdentity, sourceDigest: this.profile.sourceDigest, namespaces: this.profile.namespaces });
      const handle = await held.source.probe(held.handle, {
        nonce, generation: this.lifecycle.binding.generation, publicationScopeSha256: scope });
      const raw = readOriginalPublicationPeerReceipt(handle, held.source).observation.probe;
      if (!raw || raw.schema !== 'publication-original-nonpublisher-observation/v1' ||
          raw.nonce !== nonce || raw.serviceLabel !== expected.serviceLabel || raw.publicationScopeSha256 !== scope ||
          raw.nativeIntersection !== 'DENIED' || raw.neverReleased !== true ||
          raw.generation !== this.lifecycle.binding.generation || raw.processId !== held.value.process.processId) fail('NONPUBLISHER_PROBE');
      const { censusSourceId: _censusSourceId, ...pins } = provider;
      const common = { serviceLabel: expected.serviceLabel, definitionDigest: expected.definitionDigest,
        sourceId: source.sourceId, authorityId: source.authorityId, censusReceiptId,
        domain: this.profile.residentSource.domain, residentSnapshotSha256: args.residentSnapshotSha256,
        processId: held.value.process.processId, processStartIdentity: digest(held.value.process.startIdentity), ...pins };
      const subject = { ...common, operationId: this.operationId, binding: this.lifecycle.binding,
        fenceRevision: held.value.observation.fenceRevision };
      const probeId = this.issue('resident-nonpublisher-probe', { subject, raw, nonce });
      result.push({ ...this.base('publication-resident-nonpublisher-exclusion/v1'), ...subject,
        receiptId: this.issue('resident-nonpublisher', subject), proof: { kind: 'resident-nonpublisher-fence',
          scope: 'REGISTERED_RESIDENT_NONPUBLISHER', nativeIntersection: 'DENIED',
          ownerReceiptId: this.issue('resident-owner', subject), fenceReceiptId: this.issue('resident-namespace-fence', subject),
          sourceProbeReceiptId: probeId, sourceProbe: { schema: 'publication-resident-nonpublisher-probe/v1', ...subject,
            scope: 'REGISTERED_RESIDENT_NONPUBLISHER', nativeIntersection: 'DENIED', receiptId: probeId, nonce,
            publicationScopeSha256: scope } } });
    }
    if (result.length > 64) fail('NONPUBLISHER_PAGE_LIMIT');
    return result;
  }
  private async fence(args: Record<string, any>) {
    if (Object.keys(args).sort().join(',') !== 'censusReceiptIds' ||
        canonical(args.censusReceiptIds) !== canonical(this.censusReceiptIds)) fail('FENCE_REQUEST');
    const account = this.lifecycle.binding.accountId;
    if (await this.store.unresolvedConsumerGuardAdmissions(this.plugin, account) !== 0 ||
        await this.store.unknownNativePublicationEffects(this.plugin) !== 0) fail('FENCE_UNRESOLVED');
    const fenceId = this.issue('fence', this.lifecycle.binding);
    const oldInstances = this.historical.map(member => {
      const pages = this.pages.get(member.sourceId);
      const page = pages?.find(p => p.records.some((x: any) => x.instanceId === member.instanceId));
      if (!page) fail('HISTORY_CENSUS_REQUIRED');
      const value = { ...this.record(member), sourceId: member.sourceId, authorityId: member.authorityId,
        censusReceiptId: page.receiptId };
      return { ...value, retirementReceiptId: this.issue('old-retirement', member),
        disableReceiptId: this.issue('old-disable', member), drainReceiptId: this.issue('old-drain', member),
        fenceReceiptId: fenceId, unresolvedAdmissions: 0, unknownNativeEffects: 0 };
    });
    return { ...this.base('publication-owner-fence/v1'), censusReceiptIds: this.censusReceiptIds,
      oldAdmissions: 0, unknownNativeEffects: 0, revision: this.row!.revision,
      receiptId: this.issue('fence-observation', this.censusReceiptIds), fenceReceiptId: fenceId,
      drainReceiptId: this.issue('drain-all', this.censusReceiptIds), oldInstances };
  }
  private current(args: Record<string, any>) {
    if (Object.keys(args).sort().join(',') !== 'lifecycleSequence,receiptDigest,receiptIds,residentSnapshotSha256' ||
        !hex(args.receiptDigest) || !Array.isArray(args.receiptIds) || args.receiptIds.some((x: unknown) => !opaque(x)) ||
        new Set(args.receiptIds).size !== args.receiptIds.length || args.receiptIds.length !== this.issued.size ||
        args.receiptIds.some((x: string) => !this.issued.has(x)) || args.lifecycleSequence !== this.lifecycle.lifecycleSequence ||
        args.residentSnapshotSha256 !== this.residentSnapshot) fail('CURRENT_BINDING');
    if (this.currentDigest && (this.currentDigest !== args.receiptDigest || canonical(this.currentReceiptIds) !== canonical(args.receiptIds)))
      fail('CURRENT_CHANGED');
    this.currentDigest = args.receiptDigest; this.currentReceiptIds = [...args.receiptIds];
    return { ...this.base('publication-owner-current/v1'), root: this.profile.sourceRoot, sourceDigest: this.profile.sourceDigest,
      releaseSequence: this.lifecycle.releaseSequence, lifecycleSequence: this.lifecycle.lifecycleSequence,
      receiptDigest: args.receiptDigest, receiptIds: args.receiptIds, residentSnapshotSha256: this.residentSnapshot };
  }
  async revoke(state: 'UNKNOWN' | 'REVOKED' = 'REVOKED') {
    if (this.closed) return;
    this.closed = true; this.unsubscribe?.(); this.unsubscribe = undefined;
    // A prepared retirement remains RETIRING until its independently verified
    // original DRAINED transition wins the exact-row+history CAS. A crash does
    // not turn it into a completed retirement or permit a replay.
    if (this.retirementPrepared) return;
    if (this.row) {
      const next = { ...this.ledger, state };
      try {
        if (await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.lifecycle.binding.accountId,
            this.key, this.row, canonical(next))) this.ledger = next;
      } catch { /* No overwrite of UNKNOWN or the original competing owner. */ }
    }
  }
}
