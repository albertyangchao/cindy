/** Main-private coverage lifecycle and IO admission. No IPC, issuer-from-JSON or production registry.
 * A controlled deployment adapter is still required. Constructing this kernel is NOT runtime support.
 * The independent ConsumerGuards leaf owns the untrusted proof parser; do not import it until reviewed.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
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
  quiesce(): Promise<void>;
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
export function isConsumerGuardCoverageAuthority(
  value: unknown,
): value is ConsumerGuardCoverageAuthority {
  return typeof value === 'object' && value !== null && authorities.has(value);
}
const sha = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
const hash = (s: unknown): s is string => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const text = (s: unknown): s is string => typeof s === 'string' && s.length > 0 && s.length <= 256;
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
        report: null,
      };
      await this.save(this.stateKey, row, next);
      let q = await this.read(this.stateKey);
      try {
        await this.driver!.quiesce();
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
        this.checkControlledReport(report, generation, old.lifecycleSequence);
        // Root identity includes the release generation, even for rollback of identical files.
        if (old.usedRootIdentities.includes(this.driver!.registration.rootIdentity))
          fail('ROOT_GENERATION_REUSED');
        const ready: State = {
          ...next,
          state: 'READY',
          report: structuredClone(report),
          releaseSequence: old.releaseSequence + 1,
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
  private checkControlledReport(r: ControlledCoverageReport, generation: string, sequence: number) {
    const registration = this.driver!.registration;
    if (
      !hash(registration.rootIdentity) ||
      !hash(registration.rootDefinitionDigest) ||
      !hash(registration.inventoryDigest) ||
      !hash(registration.registrationSetDigest) ||
      !Array.isArray(registration.instances) ||
      registration.instances.length < coverageEntries.length ||
      registration.instances.length > 64 ||
      !r ||
      r.releaseGeneration !== generation ||
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
          x.length !== 1 || x[0].namespace !== 'native-publication' || !text(x[0].fenceReceiptId)
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
    this.checkControlledReport(s.report, s.releaseGeneration!, s.lifecycleSequence - 1);
    if (this.clock() >= owned.at + 30000) fail('CHALLENGE_EXPIRED');
    return Object.freeze({
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
      members: structuredClone(s.report.members),
      oldGenerationAdmissions: structuredClone(s.report.oldGenerationAdmissions),
      unknownNativeEffects: s.report.unknownNativeEffects,
      fenceRef: s.report.fenceRef,
    });
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
