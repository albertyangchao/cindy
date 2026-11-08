/** Main-private coverage lifecycle and IO admission. No IPC, issuer-from-JSON or production registry.
 * A controlled deployment adapter is still required. Constructing this kernel is NOT runtime support.
 * The independent ConsumerGuards leaf owns the untrusted proof parser; do not import it until reviewed.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { ChildProcess } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { assertConsumerGuards } from './restrictedPublicationConsumerGuards.js';
import { parseNativeFrame } from './restrictedPublicationProtocol.js';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';

export type CoverageState =
  'UNSUPPORTED' | 'CLOSED_UNVERIFIED' | 'QUIESCING' | 'READY' | 'REVOKED' | 'UNKNOWN';
export type CoverageUse =
  'stage' | 'remote-staging-prepare' | 'remote-staging-upload' | 'remote-transaction';
export const coverageEntries = [
  'canonical-producer',
  'generic-direct',
  'worksheet-ci',
  'worksheet-direct',
  'tracker-direct',
  'shared-transaction',
  'native-main-dispatch',
] as const;
export const adjacentCoverageEntries = [
  'bulk-report-sync',
  'reserved-bundle',
  'private-report-files',
  'external-subtree-publishers',
] as const;
type Member = {
  instanceId: string;
  entryId: (typeof coverageEntries)[number];
  launchAuthorityId: string;
  admissionReceiptId: string;
  releaseGeneration: string;
  guardSourceIdentity: string;
  entryDefinitionDigest: string;
  state: 'GUARDED' | 'NATIVE_NAMESPACE_DENIED' | 'RETIRED_FENCED';
  effectFenceRevision: number;
  /** Denial/retirement must be the actual controller receipt, not an absent PID. */
  dispositionReceiptId: string | null;
};
export interface CoverageRegistration {
  rootIdentity: string;
  /** Canonical Caller pin digest: paths/origin/files/import closure/interpreter. Main registration only. */
  rootDefinitionDigest: string;
  deviceScopeRef: string;
  inventoryDigest: string;
  registrationSetDigest: string;
  /** Exact closed instance set, not just seven role names. Captured by the managed controller. */
  instances: ReadonlyArray<{
    instanceId: string;
    entryId: Member['entryId'];
    entryDefinitionDigest: string;
  }>;
}
export interface ControlledCoverageReport {
  releaseGeneration: string;
  releaseSequence: number;
  lifecycleSequence: number;
  fenceRef: string;
  enrollmentReceiptId: string;
  members: Member[];
  oldGenerationAdmissions: { unresolved: number; fenceReceiptId: string };
  unknownNativeEffects: number;
  exclusions: Array<{
    entryId: (typeof adjacentCoverageEntries)[number];
    namespace: 'native-publication';
    fenceReceiptId: string;
    definitionDigest: string;
    fenceRevision: number;
  }>;
}
/** Only a real Main-managed controller may implement this seam. Nothing is registered today.
 * switchRelease runs the actual fixed install/admission/fence operations, not a proof-file reader.
 * quiesce must revoke previous admission enforcement BEFORE any controlled runtime mutation.
 * assertCurrent is synchronous at dispatch, enforcing its actual loaded generation/lease boundary.
 */
export interface ControlledCoverageDriver {
  readonly issuerId: string;
  readonly accountScopeRef: string;
  readonly registration: CoverageRegistration;
  assertCurrent(fenceRef?: string): void;
  quiesce(nextGeneration?: string): Promise<void>;
  switchRelease(generation: string, previousSequence: number): Promise<ControlledCoverageReport>;
}
const controllerHandles = new WeakMap<object, ControlledCoverageDriver>();
/** Main-only DI boundary. No renderer/Agent/child route calls this. A JSON issuer cannot be a handle.
 * Isolated tests can drive the real kernel with synthetic IO; they cannot register a production root.
 */
export function createControlledCoverageController(driver: ControlledCoverageDriver): object {
  if (
    !driver ||
    typeof driver.assertCurrent !== 'function' ||
    typeof driver.quiesce !== 'function' ||
    typeof driver.switchRelease !== 'function'
  )
    fail('CONTROLLER_UNSUPPORTED');
  const handle = Object.freeze(Object.create(null));
  controllerHandles.set(handle, driver);
  return handle;
}
const authorities = new WeakSet<object>();
const ownedManagedJobs = new WeakSet<object>();
const ownedJobContexts = new WeakMap<
  object,
  { store: object; plugin: string; account: string; device: string }
>();
export function managedJobMatchesOwner(
  value: unknown,
  store: object,
  plugin: string,
  account: string,
  device: string,
): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const context = ownedJobContexts.get(value);
  return (
    !!context &&
    context.store === store &&
    context.plugin === plugin &&
    context.account === account &&
    context.device === device
  );
}
export function isOwnedManagedPublicationJob(value: unknown): value is ManagedPublicationJob {
  return typeof value === 'object' && value !== null && ownedManagedJobs.has(value);
}
export function isConsumerGuardCoverageAuthority(
  value: unknown,
): value is ConsumerGuardCoverageAuthority {
  return typeof value === 'object' && value !== null && authorities.has(value);
}
const sha = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
const hash = (s: unknown): s is string => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const text = (s: unknown): s is string =>
  typeof s === 'string' &&
  s.length > 0 &&
  Buffer.byteLength(s, 'utf8') <= 512 &&
  !/[\u0000-\u001f\u007f-\u009f]/.test(s);
const integer = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;
function fail(code: string): never {
  throw Error('PUBLICATION_COVERAGE_' + code);
}
type Store = Pick<
  ReturnType<typeof createRestrictedPartnerStore>,
  | 'consumerGuardReceiptIdentity'
  | 'readConsumerGuardReceipt'
  | 'compareAndSwapConsumerGuardReceipt'
  | 'unresolvedConsumerGuardAdmissions'
>;
type Row = { revision: number; payload: string };
type State = {
  schema: 'publication-coverage-state/v1';
  state: CoverageState;
  boot: string;
  accountScopeRef: string;
  issuerId: string | null;
  coverageRevision: number;
  releaseSequence: number;
  lifecycleSequence: number;
  releaseGeneration: string | null;
  rootIdentity: string | null;
  usedGenerations: string[];
  usedRootIdentities: string[];
  registrationDigest: string | null;
  report: ControlledCoverageReport | null;
};
type Coordinator = { revision: number; closed: boolean; chain: Promise<unknown> };
const coordinators = new WeakMap<object, Map<string, Coordinator>>();
export interface CoverageFence {
  assertCurrent(): void;
  readonly fenceRef: string;
}

export class ConsumerGuardCoverageAuthority {
  private readonly driver: ControlledCoverageDriver | undefined;
  private readonly issuer: string | undefined;
  private readonly boot = randomUUID();
  private readonly stateKey = sha('native-publication-coverage-state/v1');
  private readonly coordinator: Coordinator;
  private readonly challenges = new Map<string, { root: string; at: number; revision: number }>();
  private lastTime = 0;
  private readonly managedJobs = new Set<{ revoke(): void }>();
  constructor(
    private readonly store: Store,
    private readonly pluginId: string,
    private readonly accountScopeRef: string,
    private readonly ownerCurrent: () => void,
    controller?: object,
    private readonly now: () => number = Date.now,
  ) {
    if (!hash(accountScopeRef) || !text(pluginId)) fail('SCOPE_INVALID');
    this.driver = controller ? controllerHandles.get(controller) : undefined;
    if (controller && !this.driver) fail('CONTROLLER_UNSUPPORTED');
    if (
      this.driver &&
      (this.driver.accountScopeRef !== accountScopeRef || !text(this.driver.issuerId))
    )
      fail('SCOPE_INVALID');
    this.issuer = this.driver?.issuerId;
    let map = coordinators.get(store.consumerGuardReceiptIdentity);
    if (!map) coordinators.set(store.consumerGuardReceiptIdentity, (map = new Map()));
    const key = pluginId + ':' + accountScopeRef;
    let coordinator = map.get(key);
    if (!coordinator)
      map.set(key, (coordinator = { revision: 0, closed: true, chain: Promise.resolve() }));
    this.coordinator = coordinator;
    // A new Main instance never inherits an in-memory lease, even over the same SQL receipts.
    this.coordinator.revision++;
    this.coordinator.closed = true;
    authorities.add(this);
  }
  private clock() {
    const t = this.now();
    if (!integer(t) || t < this.lastTime) {
      this.coordinator.revision++;
      this.coordinator.closed = true;
      fail('CLOCK_UNKNOWN');
    }
    this.lastTime = t;
    return t;
  }
  private exclusive<T>(use: () => Promise<T>): Promise<T> {
    const next = this.coordinator.chain.then(use, use);
    this.coordinator.chain = next.catch(() => {});
    return next;
  }
  private current() {
    try {
      this.ownerCurrent();
      this.clock();
      if (
        this.driver &&
        (this.driver.accountScopeRef !== this.accountScopeRef ||
          this.driver.issuerId !== this.issuer)
      )
        fail('CONTROLLER_CHANGED');
      this.driver?.assertCurrent();
    } catch (error) {
      this.coordinator.revision++;
      this.coordinator.closed = true;
      this.challenges.clear();
      throw error;
    }
  }
  private fenceCurrent(ref: string) {
    try {
      this.driver!.assertCurrent(ref);
    } catch (error) {
      this.coordinator.revision++;
      this.coordinator.closed = true;
      this.challenges.clear();
      throw error;
    }
  }
  private async read(key: string) {
    this.current();
    const row = await this.store.readConsumerGuardReceipt(this.pluginId, this.accountScopeRef, key);
    this.current();
    return row;
  }
  private async save(key: string, old: Row | undefined, value: unknown) {
    this.current();
    const ok = await this.store.compareAndSwapConsumerGuardReceipt(
      this.pluginId,
      this.accountScopeRef,
      key,
      old,
      JSON.stringify(value),
    );
    this.current();
    if (!ok) {
      this.coordinator.revision++;
      this.coordinator.closed = true;
      fail('RECEIPT_CONFLICT');
    }
    if (key === this.stateKey) {
      // Immutable transition receipts survive current-state updates and rollback. No new table.
      const auditKey = sha(['coverage-transition/v1', this.boot, (old?.revision ?? 0) + 1]);
      if (
        !(await this.store.compareAndSwapConsumerGuardReceipt(
          this.pluginId,
          this.accountScopeRef,
          auditKey,
          undefined,
          JSON.stringify(value),
        ))
      ) {
        this.coordinator.closed = true;
        fail('RECEIPT_CONFLICT');
      }
      this.current();
    }
  }
  private state(row: Row | undefined): State {
    if (!row)
      return {
        schema: 'publication-coverage-state/v1',
        state: this.driver ? 'CLOSED_UNVERIFIED' : 'UNSUPPORTED',
        boot: this.boot,
        accountScopeRef: this.accountScopeRef,
        issuerId: this.driver?.issuerId ?? null,
        coverageRevision: 0,
        releaseSequence: 0,
        lifecycleSequence: 0,
        releaseGeneration: null,
        rootIdentity: null,
        usedGenerations: [],
        usedRootIdentities: [],
        registrationDigest: null,
        report: null,
      };
    let s: State;
    try {
      s = JSON.parse(row.payload);
    } catch {
      fail('RECEIPT_UNKNOWN');
    }
    if (
      !s! ||
      s.schema !== 'publication-coverage-state/v1' ||
      s.accountScopeRef !== this.accountScopeRef ||
      !['UNSUPPORTED', 'CLOSED_UNVERIFIED', 'QUIESCING', 'READY', 'REVOKED', 'UNKNOWN'].includes(
        s.state,
      ) ||
      !integer(s.coverageRevision) ||
      s.coverageRevision >= Number.MAX_SAFE_INTEGER ||
      !integer(s.releaseSequence) ||
      s.releaseSequence >= Number.MAX_SAFE_INTEGER ||
      !integer(s.lifecycleSequence) ||
      s.lifecycleSequence >= Number.MAX_SAFE_INTEGER ||
      !Array.isArray(s.usedGenerations) ||
      s.usedGenerations.some((g) => !text(g)) ||
      new Set(s.usedGenerations).size !== s.usedGenerations.length ||
      !Array.isArray(s.usedRootIdentities) ||
      s.usedRootIdentities.some((r) => !hash(r)) ||
      new Set(s.usedRootIdentities).size !== s.usedRootIdentities.length ||
      !text(s.boot)
    )
      fail('RECEIPT_UNKNOWN');
    if (
      s.state === 'READY' &&
      (!text(s.releaseGeneration) ||
        !hash(s.rootIdentity) ||
        !hash(s.registrationDigest) ||
        !text(s.issuerId) ||
        s.coverageRevision < 1 ||
        s.releaseSequence < 1 ||
        s.lifecycleSequence < 1 ||
        !s.usedGenerations.includes(s.releaseGeneration))
    )
      fail('RECEIPT_UNKNOWN');
    return s;
  }
  async status(): Promise<CoverageState> {
    const s = this.state(await this.read(this.stateKey));
    if (!this.driver) return 'UNSUPPORTED';
    return s.boot !== this.boot || (s.state === 'READY' && this.coordinator.closed)
      ? 'UNKNOWN'
      : s.state;
  }
  /** Facts are emitted only by the bound controller's controlled switch, not supplied as a proof. */
  async switchGeneration(generation: string): Promise<void> {
    if (!this.driver) fail('CONTROLLER_UNSUPPORTED');
    if (!text(generation)) fail('GENERATION_INVALID');
    // Synchronous revocation comes before SQL or any await, including an in-flight IO callback.
    this.coordinator.revision++;
    this.coordinator.closed = true;
    const transitionRevision = this.coordinator.revision;
    this.challenges.clear();
    for (const job of this.managedJobs) job.revoke();
    return this.exclusive(async () => {
      const row = await this.read(this.stateKey),
        old = this.state(row);
      if (old.usedGenerations.includes(generation) || old.usedGenerations.length >= 1024)
        fail('GENERATION_REUSED');
      const next: State = {
        ...old,
        boot: this.boot,
        issuerId: this.driver!.issuerId,
        state: 'QUIESCING',
        coverageRevision: old.coverageRevision + 1,
        usedGenerations: [...old.usedGenerations, generation],
        releaseGeneration: generation,
        report: old.report,
      };
      await this.save(this.stateKey, row, next);
      let q = await this.read(this.stateKey);
      try {
        await this.driver!.quiesce(generation);
        this.current();
        if (
          (await this.store.unresolvedConsumerGuardAdmissions(
            this.pluginId,
            this.accountScopeRef,
          )) !== 0
        )
          fail('UNRESOLVED_ADMISSION');
        this.current();
        const report = await this.driver!.switchRelease(generation, old.lifecycleSequence);
        this.current();
        this.checkControlledReport(report, generation, old.lifecycleSequence, old.releaseSequence);
        // Root identity includes the release generation, even for rollback of identical files.
        if (old.usedRootIdentities.includes(this.driver!.registration.rootIdentity))
          fail('ROOT_GENERATION_REUSED');
        const ready: State = {
          ...next,
          state: 'READY',
          report: structuredClone(report),
          releaseSequence: report.releaseSequence,
          lifecycleSequence: report.lifecycleSequence,
          registrationDigest: sha(this.driver!.registration),
          rootIdentity: this.driver!.registration.rootIdentity,
          usedRootIdentities: [...old.usedRootIdentities, this.driver!.registration.rootIdentity],
        };
        await this.save(this.stateKey, q, ready);
        if (this.coordinator.revision !== transitionRevision) fail('LEASE_REVOKED');
        this.coordinator.closed = false;
      } catch (error) {
        this.coordinator.revision++;
        this.coordinator.closed = true;
        // Preserve QUIESCING/UNKNOWN even when the driver fails or its completion is late.
        try {
          await this.save(this.stateKey, q, { ...next, state: 'UNKNOWN' });
        } catch {
          /* never mask primary */
        }
        throw error;
      }
    });
  }
  private checkControlledReport(
    r: ControlledCoverageReport,
    generation: string,
    sequence: number,
    releaseSequence: number,
  ) {
    const registration = this.driver!.registration;
    if (
      !hash(registration.rootIdentity) ||
      !hash(registration.rootDefinitionDigest) ||
      !hash(registration.deviceScopeRef) ||
      !hash(registration.inventoryDigest) ||
      !hash(registration.registrationSetDigest) ||
      !Array.isArray(registration.instances) ||
      registration.instances.length < coverageEntries.length ||
      registration.instances.length > 64 ||
      !r ||
      r.releaseGeneration !== generation ||
      r.releaseSequence !== releaseSequence + 1 ||
      !integer(r.releaseSequence) ||
      r.lifecycleSequence !== sequence + 1 ||
      !integer(r.lifecycleSequence) ||
      !text(r.fenceRef) ||
      !text(r.enrollmentReceiptId) ||
      r.oldGenerationAdmissions?.unresolved !== 0 ||
      !text(r.oldGenerationAdmissions?.fenceReceiptId) ||
      r.unknownNativeEffects !== 0 ||
      !Array.isArray(r.members) ||
      r.members.length !== registration.instances.length ||
      !Array.isArray(r.exclusions)
    )
      fail('COVERAGE_UNKNOWN');
    const names = new Set<string>();
    for (const wanted of registration.instances) {
      const got = r.members.filter((m) => m.instanceId === wanted.instanceId);
      if (
        !text(wanted.instanceId) ||
        names.has(wanted.instanceId) ||
        got.length !== 1 ||
        !coverageEntries.includes(wanted.entryId) ||
        !hash(wanted.entryDefinitionDigest)
      )
        fail('MEMBERSHIP_UNKNOWN');
      names.add(wanted.instanceId);
      const m = got[0];
      if (
        m.entryId !== wanted.entryId ||
        m.entryDefinitionDigest !== wanted.entryDefinitionDigest ||
        m.releaseGeneration !== generation ||
        !text(m.launchAuthorityId) ||
        !text(m.admissionReceiptId) ||
        !hash(m.guardSourceIdentity) ||
        !integer(m.effectFenceRevision) ||
        m.effectFenceRevision < 1 ||
        !['GUARDED', 'NATIVE_NAMESPACE_DENIED', 'RETIRED_FENCED'].includes(m.state) ||
        (m.state !== 'GUARDED' && !text(m.dispositionReceiptId)) ||
        ([
          'canonical-producer',
          'generic-direct',
          'shared-transaction',
          'native-main-dispatch',
        ].includes(m.entryId) &&
          m.state !== 'GUARDED')
      )
        fail('MEMBERSHIP_UNKNOWN');
    }
    if (
      coverageEntries.some((id) => !r.members.some((m) => m.entryId === id)) ||
      r.exclusions.length !== adjacentCoverageEntries.length ||
      adjacentCoverageEntries.some((id) => {
        const x = r.exclusions.filter((e) => e.entryId === id);
        return (
          x.length !== 1 ||
          x[0].namespace !== 'native-publication' ||
          !text(x[0].fenceReceiptId) ||
          !hash(x[0].definitionDigest) ||
          !integer(x[0].fenceRevision) ||
          x[0].fenceRevision < 1
        );
      })
    )
      fail('NAMESPACE_UNKNOWN');
    this.fenceCurrent(r.fenceRef);
  }
  /** Called BEFORE restart/source/account/registration/rollback/disconnect mutations. */
  async invalidate(state: 'QUIESCING' | 'REVOKED' | 'UNKNOWN' = 'QUIESCING') {
    this.coordinator.revision++;
    this.coordinator.closed = true;
    this.challenges.clear();
    for (const job of this.managedJobs) job.revoke();
    if (!['QUIESCING', 'REVOKED', 'UNKNOWN'].includes(state)) fail('LIFECYCLE_STATE_INVALID');
    return this.exclusive(async () => {
      const row = await this.read(this.stateKey),
        s = this.state(row);
      await this.save(this.stateKey, row, {
        ...s,
        boot: this.boot,
        state,
        coverageRevision: s.coverageRevision + 1,
      });
      await this.driver?.quiesce();
    });
  }
  freshChallenge(expectedRoot: string): string {
    this.current();
    if (!hash(expectedRoot)) fail('ROOT_MISMATCH');
    const now = this.clock();
    for (const [key, x] of this.challenges) if (now - x.at >= 30000) this.challenges.delete(key);
    if (this.challenges.size >= 256) fail('CHALLENGE_LIMIT');
    const nonce = randomBytes(32).toString('hex');
    this.challenges.set(nonce, {
      root: expectedRoot,
      at: now,
      revision: this.coordinator.revision,
    });
    return nonce;
  }
  assertRootBinding(expectedRoot: string, rootDefinitionDigest: string) {
    this.current();
    if (this.coordinator.closed) fail('LEASE_REVOKED');
    if (
      !this.driver ||
      expectedRoot !== this.driver.registration.rootIdentity ||
      rootDefinitionDigest !== this.driver.registration.rootDefinitionDigest
    )
      fail('ROOT_MISMATCH');
  }
  async readCurrent(expectedRoot: string, challenge: string) {
    const owned = this.challenges.get(challenge);
    this.challenges.delete(challenge); // failures consume too; no replay after a raced read
    this.current();
    const issuedAt = this.clock();
    if (
      !owned ||
      owned.root !== expectedRoot ||
      owned.revision !== this.coordinator.revision ||
      issuedAt - owned.at >= 30000
    )
      fail('CHALLENGE_INVALID');
    const row = await this.read(this.stateKey),
      s = this.state(row);
    // Observed authoritative facts may not be silently restored into READY on a second read.
    // Keep the last successful report/sequences in SQL; only a controlled new generation can recover.
    if (
      this.driver &&
      s.state === 'READY' &&
      s.boot === this.boot &&
      (s.issuerId !== this.driver.issuerId ||
        s.registrationDigest !== sha(this.driver.registration))
    ) {
      try {
        await this.invalidate('UNKNOWN');
      } catch {
        /* local lease is already irrevocably closed */
      }
      fail('FACTS_CHANGED');
    }
    if (
      this.coordinator.closed ||
      !this.driver ||
      s.state !== 'READY' ||
      s.boot !== this.boot ||
      !s.report ||
      s.issuerId !== this.driver.issuerId ||
      expectedRoot !== this.driver.registration.rootIdentity ||
      expectedRoot !== s.rootIdentity ||
      s.registrationDigest !== sha(this.driver.registration) ||
      owned.revision !== this.coordinator.revision
    )
      fail('NOT_READY');
    this.checkControlledReport(
      s.report,
      s.releaseGeneration!,
      s.lifecycleSequence - 1,
      s.releaseSequence - 1,
    );
    if (this.clock() >= owned.at + 30000) fail('CHALLENGE_EXPIRED');
    const proof = Object.freeze({
      schema: 'publication-consumer-guard-evidence-contract/v1',
      issuerId: s.issuerId,
      accountScopeRef: this.accountScopeRef,
      rootIdentity: expectedRoot,
      releaseGeneration: s.releaseGeneration,
      releaseSequence: s.releaseSequence,
      inventoryDigest: this.driver.registration.inventoryDigest,
      registrationSetDigest: this.driver.registration.registrationSetDigest,
      coverageRevision: s.coverageRevision,
      lifecycleSequence: s.lifecycleSequence,
      issuedAt,
      expiresAt: Math.min(issuedAt + 30000, owned.at + 30000),
      challenge,
      closedEnrollment: true,
      // Exact 964fe89 source ABI projection. Extra provenance remains in Main's own SQL report.
      members: s.report.members.map(({ dispositionReceiptId: _disposition, ...member }) => member),
      oldGenerationAdmissions: s.report.oldGenerationAdmissions.unresolved,
      unknownNativeEffects: s.report.unknownNativeEffects,
      fenceRef: s.report.fenceRef,
    });
    // Expected comes only from the already checked Main registration + SQL/controller report.
    // The old-generation fence receipt is mandatory provenance, not a zero-counter inference.
    try {
      assertConsumerGuards(
        proof,
        {
          lifecycleState: s.state,
          issuerId: this.issuer,
          accountScopeRef: this.accountScopeRef,
          rootIdentity: this.driver.registration.rootIdentity,
          releaseGeneration: s.releaseGeneration,
          releaseSequence: s.releaseSequence,
          inventoryDigest: this.driver.registration.inventoryDigest,
          registrationSetDigest: this.driver.registration.registrationSetDigest,
          coverageRevision: s.coverageRevision,
          lifecycleSequence: s.lifecycleSequence,
          challenge,
          closedEnrollment: true,
          members: s.report.members.map(({ dispositionReceiptId: _receipt, ...member }) => member),
          oldGenerationAdmissions: s.report.oldGenerationAdmissions.unresolved,
          unknownNativeEffects: s.report.unknownNativeEffects,
          fenceRef: s.report.fenceRef,
          oldGenerationFence: { disposition: 'FENCED', fenceRef: s.report.fenceRef },
          namespaceExclusions: s.report.exclusions.map((x) => ({
            entryId: x.entryId,
            receiptId: x.fenceReceiptId,
            entryDefinitionDigest: x.definitionDigest,
            effectFenceRevision: x.fenceRevision,
          })),
        },
        this.clock(),
      );
    } catch (error) {
      await this.invalidate('UNKNOWN');
      throw error;
    }
    return proof;
  }
  /** Creates a durable owner-bound job BEFORE the fixed Caller launches a process.
   * The actual child handle/channel is held by Main; JSON, FD numbers and exit0 cannot mint it.
   * Queue IO is delegated back to Main, so a fake pipe cannot authorize a Python queue write.
   */
  async prepareManagedJob(
    root: string,
    binding: ManagedPublicationJobBinding,
    nativeCurrent: () => void,
    perform: ManagedPublicationJobIO,
  ): Promise<ManagedPublicationJob> {
    if (
      !['canonical-producer', 'generic-direct'].includes(binding.entryId) ||
      !text(binding.actionId) ||
      !integer(binding.actionRevision) ||
      binding.actionRevision < 1 ||
      !hash(binding.bindingSha256) ||
      !hash(binding.scopeSha256) ||
      !hash(binding.releaseId)
    )
      fail('JOB_BINDING_INVALID');
    const proof = await this.readCurrent(root, this.freshChallenge(root));
    const device = this.driver!.registration.deviceScopeRef;
    if (!hash(device)) fail('DEVICE_UNSUPPORTED');
    const members = proof.members.filter(
      (m) =>
        m.entryId === binding.entryId &&
        m.launchAuthorityId === this.issuer &&
        m.state === 'GUARDED',
    );
    if (members.length !== 1) fail('JOB_INSTANCE_UNSUPPORTED');
    const epoch = this.coordinator.revision,
      definition = sha(this.driver!.registration);
    const current = () => {
      nativeCurrent();
      this.current();
      if (
        this.coordinator.closed ||
        this.coordinator.revision !== epoch ||
        this.clock() >= proof.expiresAt ||
        definition !== sha(this.driver!.registration)
      )
        fail('JOB_FENCED');
      this.fenceCurrent(proof.fenceRef);
    };
    const key = sha([
      'publication-managed-job/v1',
      binding.actionId,
      binding.actionRevision,
      binding.entryId,
    ]);
    const initialNonce = randomBytes(32).toString('hex');
    const metadata: JobMetadata = {
      schema: 'publication-managed-job/v1',
      jobId: randomUUID(),
      accountScopeRef: this.accountScopeRef,
      deviceScopeRef: device,
      rootIdentity: root,
      releaseGeneration: proof.releaseGeneration!,
      instanceId: members[0].instanceId,
      entryId: binding.entryId,
      bindingSha256: binding.bindingSha256,
      scopeSha256: binding.scopeSha256,
      actionId: binding.actionId,
      actionRevision: binding.actionRevision,
      releaseId: binding.releaseId,
      coverageRevision: proof.coverageRevision,
      expiresAt: proof.expiresAt,
    };
    Object.freeze(metadata);
    await this.exclusive(async () => {
      current();
      if (await this.read(key)) fail('JOB_ALREADY_CLAIMED');
      await this.save(key, undefined, {
        ...metadata,
        state: 'UNKNOWN',
        nonceSha256: sha(initialNonce),
        createdAt: this.clock(),
      });
      current();
    });
    const update = async (suffix: string, value: unknown, once = false) =>
      this.exclusive(async () => {
        current();
        const target = suffix ? sha([key, suffix]) : key,
          old = await this.read(target);
        if (once && old) fail('JOB_OPERATION_HELD');
        await this.save(target, old, value);
        current();
      });
    if (
      binding.entryId === 'generic-direct' &&
      proof.members.filter(
        (m) =>
          m.entryId === 'native-main-dispatch' &&
          m.launchAuthorityId === this.issuer &&
          m.state === 'GUARDED',
      ).length !== 1
    )
      fail('JOB_INSTANCE_UNSUPPORTED');
    const roleInstances = Object.fromEntries(
      proof.members
        .filter((m) => m.launchAuthorityId === this.issuer && m.state === 'GUARDED')
        .map((m) => [m.entryId, m.instanceId]),
    );
    const job = new ManagedPublicationJob(
      metadata,
      initialNonce,
      roleInstances,
      current,
      perform,
      update,
      async () => ({
        proof: await this.readCurrent(root, this.freshChallenge(root)),
        registeredInstances: this.driver!.registration.instances.map((x) => x.instanceId),
        namespaceExclusions: this.state(await this.read(this.stateKey)).report!.exclusions.map(
          (e) => ({
            entryId: e.entryId,
            receiptId: e.fenceReceiptId,
            definitionDigest: e.definitionDigest,
            fenceRevision: e.fenceRevision,
          }),
        ),
      }),
      () => {
        this.managedJobs.delete(job);
        void this.invalidate('UNKNOWN').catch(() => {});
      },
      () => this.managedJobs.delete(job),
    );
    ownedManagedJobs.add(job);
    ownedJobContexts.set(job, {
      store: this.store.consumerGuardReceiptIdentity,
      plugin: this.pluginId,
      account: this.accountScopeRef,
      device,
    });
    this.managedJobs.add(job);
    return job;
  }
  /** Durable once-only claim precedes queue write / each fixed transport dispatch. No resend on UNKNOWN.
   * Read-only reconciliation is intentionally outside this effect API and cannot issue a new claim.
   */
  async withAdmission<T>(
    expectedRoot: string,
    actionId: string,
    useKind: CoverageUse,
    use: (fence: CoverageFence) => Promise<T>,
  ): Promise<T> {
    if (
      !text(actionId) ||
      !['stage', 'remote-staging-prepare', 'remote-staging-upload', 'remote-transaction'].includes(
        useKind,
      )
    )
      fail('ADMISSION_INVALID');
    const revision = this.coordinator.revision;
    const proof = await this.readCurrent(expectedRoot, this.freshChallenge(expectedRoot));
    const registrationDigest = sha(this.driver!.registration);
    const key = sha(['native-publication-admission/v1', actionId, useKind]);
    const claim = {
      schema: 'publication-coverage-admission/v1',
      actionId,
      useKind,
      accountScopeRef: this.accountScopeRef,
      rootIdentity: expectedRoot,
      releaseGeneration: proof.releaseGeneration,
      fenceRef: proof.fenceRef,
      coverageRevision: proof.coverageRevision,
      state: 'UNKNOWN',
    };
    let finished = false,
      claimed = false;
    const assertCurrent = () => {
      this.current();
      if (
        finished ||
        this.coordinator.closed ||
        revision !== this.coordinator.revision ||
        this.clock() >= proof.expiresAt ||
        expectedRoot !== this.driver?.registration.rootIdentity ||
        proof.inventoryDigest !== this.driver?.registration.inventoryDigest ||
        proof.registrationSetDigest !== this.driver?.registration.registrationSetDigest ||
        registrationDigest !== sha(this.driver?.registration)
      )
        fail('LEASE_REVOKED');
      this.fenceCurrent(proof.fenceRef);
    };
    try {
      await this.exclusive(async () => {
        assertCurrent();
        if (await this.read(key)) fail('ADMISSION_ALREADY_CLAIMED');
        assertCurrent();
        await this.save(key, undefined, claim);
        claimed = true;
        assertCurrent();
      });
      assertCurrent();
      const value = await use(Object.freeze({ assertCurrent, fenceRef: proof.fenceRef }));
      assertCurrent();
      await this.exclusive(async () => {
        assertCurrent();
        const row = await this.read(key);
        if (!row || row.payload !== JSON.stringify(claim)) fail('RECEIPT_CONFLICT');
        assertCurrent();
        await this.save(key, row, { ...claim, state: 'COMPLETE' });
        assertCurrent();
      });
      finished = true;
      return value;
    } catch (error) {
      finished = true;
      // The original UNKNOWN claim is never deleted or reset; late/failed IO does not grant retry.
      if (claimed) {
        try {
          await this.invalidate('UNKNOWN');
        } catch {
          /* preserve the original IO/permission error */
        }
      }
      throw error;
    }
  }
}

export interface ManagedPublicationJobBinding {
  entryId: 'canonical-producer' | 'generic-direct';
  actionId: string;
  actionRevision: number;
  bindingSha256: string;
  scopeSha256: string;
  releaseId: string;
}
/** Implemented only by the fixed Caller: no arbitrary command, path, URL, issuer or SQL input. */
export type ManagedPublicationJobIO = (
  operation: 'queue-write' | 'queue-archive' | 'confirm-claim' | 'confirm-session',
  payload: Record<string, unknown>,
  current: () => void,
) => Promise<unknown>;
type JobMetadata = ManagedPublicationJobBinding & {
  schema: 'publication-managed-job/v1';
  jobId: string;
  accountScopeRef: string;
  deviceScopeRef: string;
  rootIdentity: string;
  releaseGeneration: string;
  instanceId: string;
  coverageRevision: number;
  expiresAt: number;
};
/** Main-held transport endpoint. An anonymous pipe is transport, not the issuer.
 * Only this exact Main-spawned ChildProcess reaches the stored job and its current native/coverage fence.
 * Python must delegate native queue writes to this endpoint; accepting a fake peer must cause no queue IO.
 */
export class ManagedPublicationJob {
  private child?: ChildProcess;
  private controlWriter?: Writable;
  private controlReader?: Readable;
  private nonce: string;
  private sequence = 0;
  private loaded = false;
  private closed = false;
  private wire = Buffer.alloc(0);
  private chain: Promise<void> = Promise.resolve();
  private readonly claims = new Map<
    string,
    {
      operationId: string;
      requestedEntryId: string;
      requestedInstanceId: string;
      state: 'UNKNOWN' | 'COMPLETE';
    }
  >();
  constructor(
    readonly metadata: Readonly<JobMetadata>,
    initialNonce: string,
    private readonly roleInstances: Record<string, string>,
    private readonly current: () => void,
    private readonly perform: ManagedPublicationJobIO,
    private readonly update: (key: string, value: unknown, once?: boolean) => Promise<void>,
    private readonly observe: () => Promise<unknown>,
    private readonly failed: () => void,
    private readonly completed: () => void,
  ) {
    this.nonce = initialNonce;
  }
  attach(child: ChildProcess) {
    this.current();
    if (this.child || !(child instanceof ChildProcess)) fail('JOB_CHANNEL_INVALID');
    const streams = child.stdio as unknown as Array<Readable | Writable | null | undefined>;
    const writer = streams[5] as Writable | undefined,
      reader = streams[6] as Readable | undefined;
    if (!writer || !reader || typeof writer.write !== 'function' || typeof reader.on !== 'function')
      fail('JOB_CHANNEL_INVALID');
    this.controlWriter = writer;
    this.controlReader = reader;
    this.child = child;
    this.controlWriter!.on('error', () => this.revoke());
    this.controlReader!.on('error', () => this.revoke());
    this.controlReader!.on('end', () => {
      if (
        !this.closed &&
        (!this.loaded ||
          !this.claims.size ||
          [...this.claims.values()].some((c) => c.state === 'UNKNOWN'))
      )
        this.revoke();
    });
    this.controlReader!.on('data', (chunk: Buffer) => {
      if (this.closed) return;
      this.wire = Buffer.concat([this.wire, chunk]);
      if (this.wire.length > 65536) {
        this.revoke();
        return;
      }
      const at = this.wire.indexOf(10);
      if (at < 0) return;
      if (at !== this.wire.length - 1) {
        this.revoke();
        return;
      }
      const raw = this.wire.subarray(0, at);
      this.wire = Buffer.alloc(0);
      this.chain = this.chain
        .then(() => this.request(raw))
        .catch(() => {
          this.revoke();
        });
    });
    // FD5: Main->child; FD6: child->Main. No secret, command, path or authority supplied by child.
    this.controlWriter!.write(JSON.stringify({ ...this.metadata, nonce: this.nonce }) + '\n');
  }
  private async request(raw: Buffer) {
    this.current();
    if (this.closed || !this.child) fail('JOB_CLOSED');
    const m = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    if (
      !m ||
      Object.keys(m).sort().join(',') !== 'jobId,nonce,operation,payload,schema,sequence' ||
      m.schema !== this.metadata.schema ||
      m.jobId !== this.metadata.jobId ||
      m.nonce !== this.nonce ||
      m.sequence !== this.sequence ||
      !integer(m.sequence) ||
      m.sequence >= 256 ||
      !m.payload ||
      typeof m.payload !== 'object' ||
      Array.isArray(m.payload)
    )
      fail('JOB_FRAME_INVALID');
    this.sequence++;
    this.nonce = randomBytes(32).toString('hex');
    await this.update('', {
      ...this.metadata,
      state: 'UNKNOWN',
      sequence: this.sequence,
      nonceSha256: sha(this.nonce),
    });
    const keys = Object.keys(m.payload).sort().join(',');
    let result: unknown;
    if (m.operation === 'loaded' && !this.loaded && keys === 'bindingSha256,entryId') {
      if (
        m.payload.bindingSha256 !== this.metadata.bindingSha256 ||
        m.payload.entryId !== this.metadata.entryId
      )
        fail('JOB_SCOPE_INVALID');
      await this.update(
        'loaded',
        {
          ...this.metadata,
          schema: 'publication-managed-loaded/v1',
          state: 'LOADED',
          sequence: this.sequence,
        },
        true,
      );
      this.loaded = true;
      result = { state: 'LOADED' };
    } else if (!this.loaded) fail('JOB_NOT_LOADED');
    else if (m.operation === 'observe' && keys === '') result = await this.observe();
    else if (m.operation === 'claim' && keys === 'entryId,operationId') {
      const op = m.payload.operationId,
        entry = m.payload.entryId;
      const queue =
        this.metadata.entryId === 'canonical-producer' &&
        entry === 'canonical-producer' &&
        /^queue:[a-f0-9]{64}$/.test(op);
      const remote =
        this.metadata.entryId === 'generic-direct' &&
        entry === 'native-main-dispatch' &&
        ['remote-staging-prepare', 'remote-staging-upload', 'remote-transaction'].some(
          (x) => op === this.metadata.releaseId + ':' + x,
        );
      if (
        !text(op) ||
        (!queue && !remote) ||
        [...this.claims.values()].some((c) => c.operationId === op)
      )
        fail('JOB_OPERATION_DENIED');
      const claimId = randomUUID();
      const claim = {
        operationId: op,
        requestedEntryId: entry,
        requestedInstanceId: this.roleInstances[entry],
        state: 'UNKNOWN' as const,
      };
      if (!text(claim.requestedInstanceId)) fail('JOB_INSTANCE_UNSUPPORTED');
      await this.update(
        'claim:' + sha(op),
        { ...this.metadata, schema: 'publication-managed-claim/v1', claimId, ...claim },
        true,
      );
      this.claims.set(claimId, claim);
      if (!this.roleInstances[entry]) fail('JOB_INSTANCE_UNSUPPORTED');
      result = {
        instance_id: this.roleInstances[entry],
        entry_id: entry,
        generation: this.metadata.releaseGeneration,
        root_identity: this.metadata.rootIdentity,
        claim_id: claimId,
      };
    } else if (m.operation === 'assert_current' && keys === 'claimId') {
      if (!this.claims.has(m.payload.claimId)) fail('JOB_CLAIM_INVALID');
      result = { state: 'CURRENT' };
    } else if (
      ['queue-write', 'queue-archive'].includes(m.operation) &&
      keys === 'candidate,claimId'
    ) {
      const claim = this.claims.get(m.payload.claimId);
      if (
        !claim ||
        claim.state !== 'UNKNOWN' ||
        this.metadata.entryId !== 'canonical-producer' ||
        !claim.operationId.startsWith('queue:')
      )
        fail('JOB_CLAIM_INVALID');
      const candidate = m.payload.candidate;
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate))
        fail('JOB_CANDIDATE_INVALID');
      if (
        m.operation === 'queue-write' &&
        candidate.manifest?.artifact_sha256 !== claim.operationId.slice(6)
      )
        fail('JOB_SCOPE_INVALID');
      const target =
        m.operation === 'queue-write'
          ? candidate.manifest?.artifact_sha256
          : candidate.predecessorSha256;
      if (!hash(target)) fail('JOB_CANDIDATE_INVALID');
      const slot = 'io:' + m.operation + ':' + target;
      await this.update(
        slot,
        {
          ...this.metadata,
          schema: 'publication-managed-io/v1',
          state: 'UNKNOWN',
          operation: m.operation,
          candidateSha256: sha(candidate),
        },
        true,
      );
      result = await this.perform(m.operation as 'queue-write' | 'queue-archive', candidate, () => {
        this.current();
        if (this.closed) fail('JOB_CLOSED');
      });
      this.current();
      await this.update(slot, {
        ...this.metadata,
        schema: 'publication-managed-io/v1',
        state: 'COMPLETE',
        operation: m.operation,
        receipt: result,
      });
    } else if (m.operation === 'finish' && keys === 'claimId,outcome') {
      const claim = this.claims.get(m.payload.claimId);
      if (!claim || claim.state !== 'UNKNOWN' || m.payload.outcome !== 'COMPLETE')
        fail('JOB_FINISH_UNKNOWN');
      // Child COMPLETE is only a candidate: the actual Caller must have its OWN queue/dispatch receipt.
      result = await this.perform('confirm-claim', { operationId: claim.operationId }, () =>
        this.current(),
      );
      await this.update('claim:' + sha(claim.operationId), {
        ...this.metadata,
        schema: 'publication-managed-claim/v1',
        claimId: m.payload.claimId,
        operationId: claim.operationId,
        requestedEntryId: claim.requestedEntryId,
        requestedInstanceId: claim.requestedInstanceId,
        state: 'COMPLETE',
        receipt: result,
      });
      claim.state = 'COMPLETE';
    } else fail('JOB_OPERATION_DENIED');
    this.current();
    if (this.closed) fail('JOB_CLOSED');
    const reply = {
      schema: this.metadata.schema,
      jobId: this.metadata.jobId,
      sequence: this.sequence - 1,
      nextNonce: this.nonce,
      ok: true,
      result,
    };
    const wire = JSON.stringify(reply) + '\n';
    if (Buffer.byteLength(wire) > 65536) fail('JOB_FRAME_LIMIT');
    this.controlWriter!.write(wire);
  }
  revoke() {
    if (this.closed) return;
    this.closed = true;
    this.controlWriter?.destroy();
    this.controlReader?.destroy();
    this.child?.kill(); // local kill is NOT remote cancellation or a completed business receipt
    this.failed();
  }
  async finishProcess(success: boolean) {
    await this.chain;
    try {
      this.current();
      if (
        !success ||
        this.closed ||
        !this.loaded ||
        this.wire.length ||
        !this.claims.size ||
        [...this.claims.values()].some((c) => c.state !== 'COMPLETE')
      )
        fail('JOB_FINISH_UNKNOWN');
      const receipt = await this.perform('confirm-session', {}, () => this.current());
      await this.update('', { ...this.metadata, state: 'COMPLETE', receipt });
      this.closed = true;
      this.controlWriter?.destroy();
      this.controlReader?.destroy();
      this.completed();
    } catch (error) {
      this.revoke();
      throw error;
    }
  }
}
