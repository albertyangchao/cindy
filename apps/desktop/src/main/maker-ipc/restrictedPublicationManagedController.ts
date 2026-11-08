import { digest as canonicalDigest } from './restrictedPublicationProtocol.js';
/** Main-private owned publisher deployment and process lifecycle. No IPC/production registry.
 * Installation facts cover ONLY this owned release tree. Unknown external/old writers never
 * become covered merely because these files/children were installed or exited successfully.
 */
import { createHash, randomUUID } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { constants } from 'node:fs';
import { open, lstat, realpath, mkdir, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import { publicationPython, publicationManagedEntryPython } from './restrictedPublicationPython.js';
import {
  isOwnedManagedPublicationJob,
  managedJobMatchesOwner,
  type ManagedPublicationJob,
} from './restrictedPublicationConsumerGuardAuthority.js';
const hash = (x: string | Uint8Array) => createHash('sha256').update(x).digest('hex');
const sha = (x: unknown) => hash(JSON.stringify(x));
const validHash = (x: unknown): x is string => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const opaque = (x: unknown): x is string =>
  typeof x === 'string' &&
  x.length > 0 &&
  Buffer.byteLength(x) <= 512 &&
  !/[\u0000-\u001f\u007f-\u009f]/.test(x);
function deny(code: string): never {
  throw Error('PUBLICATION_MANAGED_' + code);
}
type Store = Pick<
  ReturnType<typeof createRestrictedPartnerStore>,
  | 'readConsumerGuardReceipt'
  | 'compareAndSwapConsumerGuardReceipt'
  | 'unresolvedConsumerGuardAdmissions'
  | 'unknownNativePublicationEffects'
  | 'consumerGuardReceiptIdentity'
> & Partial<Pick<ReturnType<typeof createRestrictedPartnerStore>,
  'capturePublicationOwnerHistory' | 'assertPublicationOwnerHistoryCurrent'>>;
export interface PublisherReleaseSource {
  /** Main owner-approved source/interpreter/install roots, never renderer/child parameters. */
  sourceRoot: string;
  releasesRoot: string;
  python: { path: string; sha256: string };
  files: Readonly<Record<string, string>>;
}
type Release = {
  generation: string;
  root: string;
  sourceDigest: string;
  files: Record<string, string>;
};
type Lifecycle = {
  schema: 'publication-managed-lifecycle/v1';
  accountScopeRef: string;
  deviceScopeRef: string;
  boot: string;
  state: 'QUIESCING' | 'INSTALLED' | 'ACTIVE' | 'REVOKED' | 'UNKNOWN';
  sequence: number;
  /** Independent source event counters, never inferred from RPC/SQL revisions. */
  releaseSequence: number;
  lifecycleSequence: number;
  operationId: string | null;
  sourcePhase: ManagedLifecyclePhase | null;
  usedGenerations: string[];
  release: Release | null;
};
const locks = new WeakMap<object, Promise<unknown>>();
const launches = new WeakSet<object>();
const lifecycleReceipts = new WeakMap<
  object,
  {
    owner: ManagedPublicationController;
    epoch: number;
    state: Lifecycle['state'];
    value: ManagedEnrollmentObservation;
  }
>();
export interface ManagedEnrollmentObservation {
  accountScopeRef: string;
  deviceScopeRef: string;
  boot: string;
  generation: string;
  root: string;
  sourceDigest: string;
  entryId: string;
  nonce: string;
  files: Record<string, string>;
  nativeWithoutMain: 'DENIED';
  inventoryDigest: string;
}
export function readManagedEnrollmentReceipt(
  handle: object,
  owner: ManagedPublicationController,
): Readonly<ManagedEnrollmentObservation> {
  const x = lifecycleReceipts.get(handle);
  if (!x || x.owner !== owner || !owner.receiptCurrent(x.epoch, x.value.root))
    deny('ENROLLMENT_RECEIPT');
  return structuredClone(x.value);
}
export type ManagedLifecyclePhase = 'INSTALLED' | 'ENTRY_SWITCHED' | 'LOADED' | 'REVOKED' | 'DRAINED';
export interface ManagedSourceBinding {
  accountId: string;
  deviceId: string;
  bootId: string;
  ownerEpoch: number;
  generation: string;
}
export interface ManagedLifecycleObservation {
  schema: 'publication-main-lifecycle-source/v1';
  scope: 'OWNED_CONTROLLER_ONLY';
  operationId: string;
  binding: ManagedSourceBinding;
  phase: ManagedLifecyclePhase;
  releaseSequence: number;
  lifecycleSequence: number;
  root: string;
  sourceDigest: string;
  files: Record<string, string>;
  enrollment: ManagedEnrollmentObservation | null;
  ownedJobs: number;
  unresolvedAdmissions: number;
  unknownNativeEffects: number;
}
type LifecycleReceipt = {
  owner: ManagedPublicationController;
  epoch: number;
  stateDigest: string;
  key: string;
  row: { revision: number; payload: string };
  value: ManagedLifecycleObservation;
};
const managedLifecycleReceipts = new WeakMap<object, LifecycleReceipt>();
export interface PreparedInstallObservation {
  scope: 'OWNED_RELEASE_PREPARED_ONLY';
  generation: string;
  operationId: string;
  root: string;
  sourceDigest: string;
  files: Record<string, string>;
}
type PreparedInstall = {
  owner: ManagedPublicationController;
  epoch: number;
  drainedHandle: object;
  key: string;
  row: { revision: number; payload: string };
  lifecycleRow: { revision: number; payload: string };
  source: PublisherReleaseSource;
  value: PreparedInstallObservation;
  consumed: boolean;
};
const preparedInstalls = new WeakMap<object, PreparedInstall>();
/** A summary never restores this one-use, original-controller capability. */
export function readPreparedInstallReceipt(handle: object, owner: ManagedPublicationController): Readonly<PreparedInstallObservation> {
  const receipt = preparedInstalls.get(handle);
  if (!receipt || receipt.owner !== owner || receipt.consumed) deny('PREPARED_INSTALL_HANDLE');
  if (readManagedLifecycleReceipt(receipt.drainedHandle, owner).phase !== 'DRAINED') deny('PREPARED_INSTALL_DRAIN');
  return structuredClone(receipt.value);
}
/** Summaries are transport data; only the original Main-private handle can name a source fact. */
export function readManagedLifecycleReceipt(
  handle: object,
  owner: ManagedPublicationController,
): Readonly<ManagedLifecycleObservation> {
  const receipt = managedLifecycleReceipts.get(handle);
  if (
    !receipt ||
    receipt.owner !== owner ||
    !owner.lifecycleReceiptCurrent(receipt.epoch, receipt.value)
  )
    deny('LIFECYCLE_RECEIPT');
  return structuredClone(receipt.value);
}
export class ManagedPublicationController {
  private readonly boot = randomUUID();
  private readonly key = sha('publication-managed-lifecycle/v1');
  private closed = true;
  private ledgerFloor = 0;
  private sequenceFloor = 0;
  private releaseSequenceFloor = 0;
  private lifecycleSequenceFloor = 0;
  private completedLifecycle?: {
    epoch: number;
    phase: ManagedLifecyclePhase;
    stateDigest: string;
    enrollment?: object;
    receipt?: object;
  };
  private readonly sourceInvalidations = new Set<() => void>();
  private epoch = 0;
  private release?: Release;
  private readonly jobs = new Map<
    string,
    { child: ChildProcess; job: ManagedPublicationJob; settled: Promise<void> }
  >();
  constructor(
    private readonly store: Store,
    private readonly plugin: string,
    readonly accountScopeRef: string,
    private readonly deviceScopeRef: string,
    private readonly ownerCurrent: () => void,
  ) {
    if (!validHash(accountScopeRef) || !validHash(deviceScopeRef) || !opaque(plugin)) deny('SCOPE');
  }
  private async exclusive<T>(use: () => Promise<T>): Promise<T> {
    const previous = locks.get(this.store.consumerGuardReceiptIdentity) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(use);
    locks.set(
      this.store.consumerGuardReceiptIdentity,
      next.catch(() => {}),
    );
    return next;
  }
  private assertEpoch(epoch: number) {
    this.ownerCurrent();
    if (epoch !== this.epoch) deny('REVOKED');
  }
  private invalidate() {
    this.closed = true;
    ++this.epoch;
    this.completedLifecycle = undefined;
    for (const listener of [...this.sourceInvalidations]) {
      try {
        listener();
      } catch {
        // A closed source remains closed even if a consumer's cleanup fails.
      }
    }
    return this.epoch;
  }
  /** Main brokers subscribe so their held source lease closes before transition I/O. */
  onSourceInvalidated(listener: () => void): () => void {
    this.sourceInvalidations.add(listener);
    return () => this.sourceInvalidations.delete(listener);
  }
  private completeLifecycle(
    phase: ManagedLifecyclePhase,
    state: Lifecycle,
    epoch: number,
    enrollment?: object,
  ) {
    this.assertEpoch(epoch);
    this.completedLifecycle = { epoch, phase, stateDigest: sha(state), enrollment };
  }
  private async write(state: Lifecycle, epoch: number, requireDrained = false, history?: object,
    expectedPrevious?: { revision: number; payload: string }) {
    this.assertEpoch(epoch);
    if (![state.sequence, state.releaseSequence, state.lifecycleSequence].every(
      (value) => Number.isSafeInteger(value) && value >= 0,
    )) deny('SEQUENCE');
    const old = await this.store.readConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
    );
    this.assertEpoch(epoch);
    if (expectedPrevious && (!old || old.revision !== expectedPrevious.revision ||
        old.payload !== expectedPrevious.payload)) deny('CAS');
    if (old) {
      let existing: Lifecycle;
      try {
        existing = JSON.parse(old.payload);
      } catch {
        deny('LEDGER');
      }
      if (
        existing.schema !== 'publication-managed-lifecycle/v1' ||
        existing.accountScopeRef !== this.accountScopeRef ||
        existing.deviceScopeRef !== this.deviceScopeRef
      )
        deny('LEDGER');
      if (existing.boot !== this.boot && existing.state !== 'REVOKED') deny('FOREIGN_OWNER_HELD');
    }
    const ok = await this.store.compareAndSwapConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
      expectedPrevious ?? old,
      JSON.stringify(state),
      requireDrained,
      history,
    );
    this.assertEpoch(epoch);
    if (!ok) deny('CAS');
    this.ledgerFloor = Math.max(this.ledgerFloor, (old?.revision ?? 0) + 1);
    this.sequenceFloor = Math.max(this.sequenceFloor, state.sequence);
    this.releaseSequenceFloor = Math.max(this.releaseSequenceFloor, state.releaseSequence);
    this.lifecycleSequenceFloor = Math.max(this.lifecycleSequenceFloor, state.lifecycleSequence);
    const auditKey = sha(['publication-managed-event/v1', this.boot, (old?.revision ?? 0) + 1]);
    if (
      !(await this.store.compareAndSwapConsumerGuardReceipt(
        this.plugin,
        this.accountScopeRef,
        auditKey,
        undefined,
        JSON.stringify({
          schema: 'publication-managed-event/v1',
          state,
          revision: (old?.revision ?? 0) + 1,
        }),
      ))
    )
      deny('CAS');
    this.assertEpoch(epoch);
  }
  private async state(epoch: number = this.epoch): Promise<Lifecycle> {
    const row = await this.store.readConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
    );
    this.assertEpoch(epoch);
    if (!row) {
      if (this.ledgerFloor || this.sequenceFloor || this.releaseSequenceFloor || this.lifecycleSequenceFloor) {
        this.invalidate();
        deny('LEDGER_ROLLBACK');
      }
      return {
        schema: 'publication-managed-lifecycle/v1',
        accountScopeRef: this.accountScopeRef,
        deviceScopeRef: this.deviceScopeRef,
        boot: this.boot,
        state: 'QUIESCING',
        sequence: 0,
        releaseSequence: 0,
        lifecycleSequence: 0,
        operationId: null,
        sourcePhase: null,
        usedGenerations: [],
        release: null,
      };
    }
    let s: Lifecycle;
    try {
      s = JSON.parse(row.payload);
    } catch {
      deny('LEDGER');
    }
    // Old v1 rows remain readable. They carry no new source authority: a completed
    // operation in this controller is additionally required before issuing a handle.
    if ([s.releaseSequence, s.lifecycleSequence, s.operationId, s.sourcePhase].every(
      (value) => value === undefined,
    )) {
      s = { ...s, releaseSequence: 0, lifecycleSequence: 0, operationId: null, sourcePhase: null };
    }
    if (
      s.schema !== 'publication-managed-lifecycle/v1' ||
      s.accountScopeRef !== this.accountScopeRef ||
      s.deviceScopeRef !== this.deviceScopeRef ||
      !opaque(s.boot) ||
      !['QUIESCING', 'INSTALLED', 'ACTIVE', 'REVOKED', 'UNKNOWN'].includes(s.state) ||
      !Number.isSafeInteger(s.sequence) ||
      s.sequence < 0 ||
      !Number.isSafeInteger(s.releaseSequence) ||
      s.releaseSequence < 0 ||
      !Number.isSafeInteger(s.lifecycleSequence) ||
      s.lifecycleSequence < 0 ||
      (s.operationId !== null && !opaque(s.operationId)) ||
      (s.sourcePhase !== null && !['INSTALLED', 'ENTRY_SWITCHED', 'LOADED', 'REVOKED', 'DRAINED'].includes(s.sourcePhase)) ||
      !Array.isArray(s.usedGenerations) ||
      s.usedGenerations.some((x) => !opaque(x))
    )
      deny('LEDGER');
    if (
      row.revision < this.ledgerFloor ||
      s.sequence < this.sequenceFloor ||
      s.releaseSequence < this.releaseSequenceFloor ||
      s.lifecycleSequence < this.lifecycleSequenceFloor
    ) {
      this.invalidate();
      deny('LEDGER_ROLLBACK');
    }
    this.ledgerFloor = Math.max(this.ledgerFloor, row.revision);
    this.sequenceFloor = Math.max(this.sequenceFloor, s.sequence);
    this.releaseSequenceFloor = Math.max(this.releaseSequenceFloor, s.releaseSequence);
    this.lifecycleSequenceFloor = Math.max(this.lifecycleSequenceFloor, s.lifecycleSequence);
    // Restart never inherits an ACTIVE process set or a previously verified release lease.
    if (s.boot !== this.boot && s.state === 'ACTIVE') return { ...s, state: 'UNKNOWN' };
    return s;
  }
  private async directory(p: string) {
    this.ownerCurrent();
    if (!path.isAbsolute(p) || (await realpath(p)) !== p) deny('PATH');
    const s = await lstat(p);
    if (
      !s.isDirectory() ||
      s.isSymbolicLink() ||
      s.mode & 0o022 ||
      (process.getuid && s.uid !== process.getuid())
    )
      deny('PATH');
    this.ownerCurrent();
  }
  private async bytes(root: string, relative: string, expected: string) {
    if (
      !relative ||
      relative.includes('\\') ||
      relative.split('/').some((p) => !p || p === '.' || p === '..') ||
      !validHash(expected)
    )
      deny('SOURCE');
    let parent = root;
    for (const part of relative.split('/').slice(0, -1)) {
      parent = path.join(parent, part);
      await this.directory(parent);
    }
    const fd = await open(path.join(root, relative), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await fd.stat();
      if (
        !before.isFile() ||
        before.nlink !== 1 ||
        before.size > 8 * 1024 * 1024 ||
        before.mode & 0o022 ||
        (process.getuid && before.uid !== process.getuid())
      )
        deny('SOURCE');
      const data = await fd.readFile(),
        after = await fd.stat();
      this.ownerCurrent();
      if (
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs ||
        hash(data) !== expected
      )
        deny('SOURCE_DRIFT');
      return data;
    } finally {
      await fd.close();
    }
  }
  /** Revoke in-memory admissions synchronously, before waiting for any ledger/system IO. */
  async revoke(): Promise<void> {
    const epoch = this.invalidate();
    for (const x of this.jobs.values()) x.job.revoke();
    await this.exclusive(async () => {
      this.assertEpoch(epoch);
      const s = await this.state();
      this.assertEpoch(epoch);
      await this.write({ ...s, boot: this.boot, state: 'QUIESCING', sequence: s.sequence + 1 }, epoch);
      const revoked: Lifecycle = {
        ...s, boot: this.boot, state: 'REVOKED', sequence: s.sequence + 2,
        sourcePhase: 'REVOKED', lifecycleSequence: s.lifecycleSequence + 1,
      };
      await this.write(revoked, epoch);
      this.completeLifecycle('REVOKED', revoked, epoch);
    });
  }
  async drain(timeoutMs = 10000): Promise<void> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 30000) deny('TIMEOUT');
    const epoch = this.invalidate();
    await this.exclusive(async () => {
      this.assertEpoch(epoch);
      const s = await this.state();
      this.assertEpoch(epoch);
      await this.write({ ...s, state: 'QUIESCING', sequence: s.sequence + 1 }, epoch);
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        Promise.all([...this.jobs.values()].map((x) => x.settled)),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(Error('PUBLICATION_MANAGED_DRAIN_UNKNOWN')), timeoutMs);
        }),
      ]);
      this.assertEpoch(epoch);
      const unresolved = await this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.accountScopeRef);
      this.assertEpoch(epoch);
      const nativeUnknown = await this.store.unknownNativePublicationEffects(this.plugin);
      this.assertEpoch(epoch);
      if (this.jobs.size || unresolved !== 0 || nativeUnknown !== 0) deny('DRAIN_UNKNOWN');
      await this.exclusive(async () => {
        this.assertEpoch(epoch);
        const s = await this.state();
        this.assertEpoch(epoch);
        const drained: Lifecycle = {
          ...s, state: 'REVOKED', sequence: s.sequence + 1,
          sourcePhase: 'DRAINED', lifecycleSequence: s.lifecycleSequence + 1,
        };
        await this.write(drained, epoch);
        this.completeLifecycle('DRAINED', drained, epoch);
      });
    } catch (error) {
      // A late old drain must never close or overwrite a newer installed generation.
      if (epoch === this.epoch) {
        this.closed = true;
        this.completedLifecycle = undefined;
        await this.exclusive(async () => {
          this.assertEpoch(epoch);
          const s = await this.state();
          this.assertEpoch(epoch);
          await this.write({ ...s, state: 'UNKNOWN', sequence: s.sequence + 1 }, epoch);
        });
      }
      throw error;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  private preparedKey(generation: string) {
    return sha(['publication-managed-prepared-install/v1', this.deviceScopeRef, generation]);
  }
  private async preparationHistory() {
    if (!this.store.capturePublicationOwnerHistory || !this.store.assertPublicationOwnerHistoryCurrent)
      deny('ORIGINAL_HISTORY_REQUIRED');
    return this.store.capturePublicationOwnerHistory(this.plugin, this.accountScopeRef);
  }
  private async stageRelease(source: PublisherReleaseSource, generation: string, epoch: number): Promise<Release> {
    const files = { ...source.files };
    if (!Object.keys(files).length || Object.keys(files).length > 512 ||
        !files['bridge_core/publication_consumer_controller.py'] ||
        !files['scripts/publish_generic_html_direct.py']) deny('SOURCE');
    await this.directory(source.sourceRoot);
    await this.directory(source.releasesRoot);
    const pythonRoot = path.dirname(source.python.path);
    await this.directory(pythonRoot);
    await this.bytes(pythonRoot, path.basename(source.python.path), source.python.sha256);
    const target = path.join(source.releasesRoot, sha([this.accountScopeRef, this.deviceScopeRef, generation]));
    this.assertEpoch(epoch);
    await mkdir(target, { mode: 0o700 });
    let totalBytes = 0;
    for (const [relative, expected] of Object.entries(files)) {
      const data = await this.bytes(source.sourceRoot, relative, expected);
      totalBytes += data.byteLength;
      if (totalBytes > 64 * 1024 * 1024) deny('SOURCE_BUDGET');
      this.assertEpoch(epoch);
      const destination = path.join(target, relative);
      await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      const temp = destination + '.install-' + randomUUID();
      const fd = await open(temp, 'wx', 0o600);
      try { await fd.writeFile(data); await fd.sync(); }
      finally { await fd.close(); }
      this.ownerCurrent();
      if (epoch !== this.epoch) { await unlink(temp); deny('REVOKED'); }
      await rename(temp, destination);
      await this.bytes(target, relative, expected);
    }
    this.assertEpoch(epoch);
    return { generation, root: target, sourceDigest: sha(files), files };
  }
  /** Stage only an owned immutable tree while the exact old DRAINED receipt
   * remains current. The irreversible claim precedes the first filesystem write;
   * failure retains UNKNOWN and the partial directory, with no replay path. */
  async prepareInstall(source: PublisherReleaseSource, generation: string, operationId: string,
    drainedHandle: object): Promise<object> {
    source = structuredClone(source);
    const epoch = this.epoch;
    return this.exclusive(async () => {
      this.assertEpoch(epoch);
      const drained = await this.verifyLifecycleReceipt(drainedHandle);
      if (drained.phase !== 'DRAINED' || !this.closed || drained.ownedJobs !== 0 ||
          drained.unresolvedAdmissions !== 0 || drained.unknownNativeEffects !== 0) deny('PREPARED_INSTALL_DRAIN');
      const state = await this.state(epoch);
      if (!opaque(generation) || !opaque(operationId) || generation === drained.binding.generation ||
          operationId === drained.operationId || state.usedGenerations.includes(generation) ||
          state.usedGenerations.length >= 1024) deny('GENERATION');
      const lifecycleRow = await this.store.readConsumerGuardReceipt(this.plugin, this.accountScopeRef, this.key);
      if (!lifecycleRow || sha(JSON.parse(lifecycleRow.payload)) !== sha(state)) deny('PREPARED_INSTALL_DRAIN');
      const key = this.preparedKey(generation);
      if (await this.store.readConsumerGuardReceipt(this.plugin, this.accountScopeRef, key)) deny('GENERATION_PREPARED');
      this.assertEpoch(epoch);
      const claim = { schema: 'publication-managed-prepared-install/v1', state: 'UNKNOWN',
        preparationPhase: 'CLAIMED_ONLY',
        accountScopeRef: this.accountScopeRef, deviceScopeRef: this.deviceScopeRef,
        boot: this.boot, generation, operationId, originalDrain: canonicalDigest(drained),
        sourceDigest: canonicalDigest(source) };
      let row = { revision: 1, payload: JSON.stringify(claim) };
      // The first INSERT is only an irreversible reservation, never admission.
      // The Store's atomic history/native-drain predicate applies to UPDATE.
      if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.accountScopeRef,
          key, undefined, row.payload)) deny('GENERATION_PREPARED');
      const history = await this.preparationHistory();
      this.assertEpoch(epoch);
      const staging = JSON.stringify({ ...claim, preparationPhase: 'STAGING' });
      if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.accountScopeRef,
          key, row, staging, true, history)) deny('GENERATION_PREPARED');
      row = { revision: row.revision + 1, payload: staging };
      // Nothing below changes the original lifecycle row or its epoch.
      const release = await this.stageRelease(source, generation, epoch);
      await this.verifyLifecycleReceipt(drainedHandle);
      const handle = Object.freeze(Object.create(null)) as object;
      const receipt: PreparedInstall = { owner: this, epoch, drainedHandle, key, row, lifecycleRow, source,
        value: { scope: 'OWNED_RELEASE_PREPARED_ONLY', operationId, ...release }, consumed: false };
      await this.verifyPreparedRecord(receipt);
      preparedInstalls.set(handle, receipt);
      return handle;
    });
  }
  private async verifyPreparedRecord(receipt: PreparedInstall) {
    this.assertEpoch(receipt.epoch);
    const verifyOriginalRow = async () => {
      const original = await this.store.readConsumerGuardReceipt(this.plugin, this.accountScopeRef, this.key);
      if (!original || original.revision !== receipt.lifecycleRow.revision ||
          original.payload !== receipt.lifecycleRow.payload) deny('PREPARED_INSTALL_DRAIN');
    };
    await verifyOriginalRow();
    const drained = await this.verifyLifecycleReceipt(receipt.drainedHandle);
    if (drained.phase !== 'DRAINED' || !this.closed || this.jobs.size ||
        await this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.accountScopeRef) !== 0 ||
        await this.store.unknownNativePublicationEffects(this.plugin) !== 0) deny('PREPARED_INSTALL_DRAIN');
    const row = await this.store.readConsumerGuardReceipt(this.plugin, this.accountScopeRef, receipt.key);
    if (!row || row.revision !== receipt.row.revision || row.payload !== receipt.row.payload) deny('PREPARED_INSTALL_CLAIM');
    await this.directory(receipt.value.root);
    const pythonRoot = path.dirname(receipt.source.python.path);
    await this.directory(pythonRoot);
    await this.bytes(pythonRoot, path.basename(receipt.source.python.path), receipt.source.python.sha256);
    for (const [relative, expected] of Object.entries(receipt.value.files))
      await this.bytes(receipt.value.root, relative, expected);
    await verifyOriginalRow();
    await this.verifyLifecycleReceipt(receipt.drainedHandle);
    this.assertEpoch(receipt.epoch);
    return structuredClone(receipt.value);
  }
  async verifyPreparedInstall(handle: object): Promise<Readonly<PreparedInstallObservation>> {
    const receipt = preparedInstalls.get(handle);
    if (!receipt || receipt.owner !== this || receipt.consumed) deny('PREPARED_INSTALL_HANDLE');
    try { return await this.verifyPreparedRecord(receipt); }
    catch (error) { receipt.consumed = true; throw error; }
  }
  /** Called only after the original policy/entry cutover succeeds. This commits
   * the owned tree, never supplies foreign-owner coverage or a production root. */
  async commitPreparedInstall(handle: object): Promise<Release> {
    const receipt = preparedInstalls.get(handle);
    if (!receipt || receipt.owner !== this || receipt.consumed) deny('PREPARED_INSTALL_HANDLE');
    receipt.consumed = true; // before any await, including another commit call
    return this.exclusive(async () => {
      let epoch = receipt.epoch;
      let proposed: Lifecycle | undefined;
      try {
        await this.verifyPreparedRecord(receipt);
        const old = await this.state(epoch);
        const committing = JSON.stringify({ ...JSON.parse(receipt.row.payload), state: 'COMMITTING_UNKNOWN' });
        const before = await this.preparationHistory();
        this.assertEpoch(epoch);
        if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.accountScopeRef,
            receipt.key, receipt.row, committing, true, before)) deny('PREPARED_INSTALL_CLAIM');
        receipt.row = { revision: receipt.row.revision + 1, payload: committing };
        this.assertEpoch(epoch);
        epoch = this.invalidate();
        const { scope: _scope, operationId, ...release } = receipt.value;
        const installed: Lifecycle = { ...old, boot: this.boot, state: 'INSTALLED', release,
          operationId, usedGenerations: [...old.usedGenerations, release.generation],
          sequence: old.sequence + 1, releaseSequence: old.releaseSequence + 1,
          lifecycleSequence: old.lifecycleSequence + 1, sourcePhase: 'INSTALLED' };
        proposed = installed;
        const history = await this.preparationHistory();
        await this.write(installed, epoch, true, history, receipt.lifecycleRow);
        const committed = JSON.stringify({ ...JSON.parse(receipt.row.payload), state: 'COMMITTED' });
        const after = await this.preparationHistory();
        this.assertEpoch(epoch);
        if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.accountScopeRef,
            receipt.key, receipt.row, committed, true, after)) deny('PREPARED_INSTALL_CLAIM');
        this.assertEpoch(epoch);
        this.release = structuredClone(release);
        this.completeLifecycle('INSTALLED', installed, epoch);
        return structuredClone(release);
      } catch (error) {
        // Do not overwrite a newer controller epoch or another durable winner.
        if (epoch === this.epoch) {
          this.closed = true;
          this.completedLifecycle = undefined;
          // Only our exact old row, or the exact row this commit could have
          // written, may be closed. Never read a DB winner and overwrite it.
          const original = JSON.parse(receipt.lifecycleRow.payload) as Lifecycle;
          const candidates = [
            ...(proposed ? [{ state: proposed, row: { revision: receipt.lifecycleRow.revision + 1,
              payload: JSON.stringify(proposed) } }] : []),
            { state: original, row: receipt.lifecycleRow },
          ];
          for (const candidate of candidates) {
            try {
              await this.write({ ...candidate.state, state: 'UNKNOWN', sequence: candidate.state.sequence + 1 },
                epoch, false, undefined, candidate.row);
              break;
            } catch { /* Preserve the original uncertain claim and any new DB/epoch winner. */ }
          }
        }
        throw error;
      }
    });
  }
  /** Copy a pinned import closure to an immutable generation directory; never mutate old release.
   * A failure keeps the partial directory and UNKNOWN receipt, not an apparently complete install.
   */
  async install(
    source: PublisherReleaseSource,
    generation: string,
    operationId: string = generation,
  ): Promise<Release> {
    source = structuredClone(source);
    const epoch = this.invalidate();
    return this.exclusive(async () => {
      this.assertEpoch(epoch);
      const s = await this.state();
      this.assertEpoch(epoch);
      if (
        !opaque(operationId) ||
        !opaque(generation) ||
        s.usedGenerations.includes(generation) ||
        s.usedGenerations.length >= 1024
      )
        deny('GENERATION');
      if (await this.store.readConsumerGuardReceipt(this.plugin, this.accountScopeRef, this.preparedKey(generation)))
        deny('GENERATION_PREPARED');
      this.assertEpoch(epoch);
      await this.write({
        ...s,
        boot: this.boot,
        state: 'QUIESCING',
        sequence: s.sequence + 1,
        usedGenerations: [...s.usedGenerations, generation],
      }, epoch);
      try {
        if (
          this.jobs.size ||
          (await this.store.unresolvedConsumerGuardAdmissions(
            this.plugin,
            this.accountScopeRef,
          )) !== 0
        )
          deny('DRAIN_UNKNOWN');
        const release = await this.stageRelease(source, generation, epoch);
        this.assertEpoch(epoch);
        const current = await this.state();
        this.assertEpoch(epoch);
        const installed: Lifecycle = {
          ...current, boot: this.boot, state: 'INSTALLED', release, operationId,
          sequence: current.sequence + 1,
          releaseSequence: current.releaseSequence + 1,
          lifecycleSequence: current.lifecycleSequence + 1,
          sourcePhase: 'INSTALLED',
        };
        await this.write(installed, epoch);
        this.release = release;
        this.completeLifecycle('INSTALLED', installed, epoch);
        return structuredClone(release);
      } catch (error) {
        if (epoch === this.epoch) {
          this.completedLifecycle = undefined;
          const current = await this.state();
          this.assertEpoch(epoch);
          await this.write({ ...current, state: 'UNKNOWN', sequence: current.sequence + 1 }, epoch);
        }
        throw error;
      }
    });
  }
  /** Activate ONLY this owned installed entry tree. This is not global coverage or a READY issuer. */
  async switchEntry(generation: string): Promise<void> {
    const epoch = this.invalidate();
    await this.exclusive(async () => {
      this.assertEpoch(epoch);
      const s = await this.state();
      this.ownerCurrent();
      if (epoch !== this.epoch) deny('REVOKED');
      if (
        s.state !== 'INSTALLED' ||
        s.boot !== this.boot ||
        !s.release ||
        s.release.generation !== generation ||
        this.jobs.size
      )
        deny('SWITCH');
      for (const [relative, expected] of Object.entries(s.release.files))
        await this.bytes(s.release.root, relative, expected);
      if (epoch !== this.epoch) deny('REVOKED');
      const switched: Lifecycle = {
        ...s, state: 'ACTIVE', sequence: s.sequence + 1,
        sourcePhase: 'ENTRY_SWITCHED', lifecycleSequence: s.lifecycleSequence + 1,
      };
      await this.write(switched, epoch);
      this.assertEpoch(epoch);
      this.release = s.release;
      this.closed = false;
      this.completeLifecycle('ENTRY_SWITCHED', switched, epoch);
    });
  }
  /** Only an Authority-created durable job can request this fixed generic entry.
   * FD5/6 is attached by Main to its actual ChildProcess; no generic argv/shell/entry input.
   */
  async prepareOwnedChild(
    job: ManagedPublicationJob,
    source: PublisherReleaseSource,
    request:
      | { operation: 'stage'; artifacts: string; queue: string }
      | {
          operation: 'generic';
          slug: string;
          artifactSha256: string;
          artifacts: string;
          queue: string;
        },
  ): Promise<() => ChildProcess> {
    source = structuredClone(source);
    request = structuredClone(request);
    this.ownerCurrent();
    const release = this.release,
      epoch = this.epoch;
    if (
      !['stage', 'generic'].includes(request.operation) ||
      Object.keys(request).sort().join(',') !==
        (request.operation === 'stage'
          ? 'artifacts,operation,queue'
          : 'artifactSha256,artifacts,operation,queue,slug')
    )
      deny('LAUNCH');
    if (launches.has(job)) deny('LAUNCH_ALREADY_CLAIMED');
    if (
      this.closed ||
      !release ||
      !isOwnedManagedPublicationJob(job) ||
      !managedJobMatchesOwner(
        job,
        this.store.consumerGuardReceiptIdentity,
        this.plugin,
        this.accountScopeRef,
        this.deviceScopeRef,
      ) ||
      job.metadata.accountScopeRef !== this.accountScopeRef ||
      job.metadata.deviceScopeRef !== this.deviceScopeRef ||
      job.metadata.releaseGeneration !== release.generation ||
      job.metadata.entryId !==
        (request.operation === 'stage' ? 'canonical-producer' : 'generic-direct')
    )
      deny('LAUNCH');
    if (
      request.operation === 'generic' &&
      (!/^imessage-[a-f0-9]{32}$/.test(request.slug) || !validHash(request.artifactSha256))
    )
      deny('LAUNCH');
    if (sha(source.files) !== release.sourceDigest) deny('SOURCE_DRIFT');
    for (const [relative, expected] of Object.entries(release.files))
      await this.bytes(release.root, relative, expected);
    await this.bytes(
      path.dirname(source.python.path),
      path.basename(source.python.path),
      source.python.sha256,
    );
    await this.directory(request.artifacts);
    await this.directory(request.queue);
    this.ownerCurrent();
    if (this.closed || epoch !== this.epoch) deny('REVOKED');
    launches.add(job);
    await this.verifyCurrent(release.root);
    const { schema: _schema, jobId: _job, expiresAt: _expiry, ...expected } = job.metadata;
    let used = false;
    return () => {
      this.ownerCurrent();
      if (used || this.closed || epoch !== this.epoch) deny('REVOKED');
      used = true;
      const argv =
        request.operation === 'stage'
          ? ['-I', '-c', publicationPython, release.root]
          : [
              '-I',
              '-c',
              publicationManagedEntryPython,
              release.root,
              JSON.stringify(expected),
              '--apply',
              '--slug',
              request.slug,
              '--artifact-sha256',
              request.artifactSha256,
              '--native-control-read-fd',
              '3',
              '--native-control-write-fd',
              '4',
            ];
      const child = spawn(source.python.path, argv, {
        cwd: release.root,
        env: {
          PATH: '/usr/bin:/bin',
          LANG: 'en_US.UTF-8',
          PYTHONDONTWRITEBYTECODE: '1',
          BRIDGE_REPORTS_LOCAL_DIR: request.artifacts,
          BRIDGE_REPORT_QUEUE_DIR: request.queue,
          BRIDGE_REPORT_SYNC_AFTER_PUBLISH: '1',
        },
        stdio:
          request.operation === 'stage'
            ? ['pipe', 'pipe', 'pipe', 'ignore', 'ignore', 'pipe', 'pipe']
            : ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
      });
      // Caller attaches FD3/4 and job FD5/6 immediately. A process close is only a drain
      // fact: actual operation completion must independently settle in Main's account ledger.
      const settled = new Promise<void>((resolve, reject) => {
        child.once('error', reject);
        child.once('close', () => resolve());
      }).finally(() => {
        if (this.jobs.get(job.metadata.jobId)?.child === child) this.jobs.delete(job.metadata.jobId);
      });
      // Keep rejected launch completion observed; drain() and account receipts preserve UNKNOWN.
      void settled.catch(() => {
        if (epoch === this.epoch) this.invalidate();
      });
      this.jobs.set(job.metadata.jobId, { child, job, settled });
      return child;
    };
  }
  async verifyCurrent(root: string): Promise<void> {
    const epoch = this.epoch;
    try {
      this.assertCurrent(root);
      const s = await this.state();
      this.assertEpoch(epoch);
      this.assertCurrent(root);
      if (
        s.boot !== this.boot ||
        s.state !== 'ACTIVE' ||
        !s.release ||
        sha(s.release) !== sha(this.release)
      )
        deny('LEDGER_DRIFT');
    } catch (error) {
      // Restoring an old payload cannot relatch an already rejected live owner.
      if (epoch === this.epoch) this.invalidate();
      throw error;
    }
  }
  assertCurrent(root: string): void {
    this.ownerCurrent();
    if (this.closed || !this.release || this.release.root !== root) deny('REVOKED');
  }
  /** Main-owned no-business probe. It needs no action, READY lease or paid/job claim. */
  async probeEnrollment(source: PublisherReleaseSource, entryId: string): Promise<object> {
    if (
      ![
        'canonical-producer',
        'generic-direct',
        'worksheet-ci',
        'worksheet-direct',
        'tracker-direct',
        'shared-transaction',
        'owned-namespace-source',
      ].includes(entryId)
    )
      deny('PROBE_ENTRY');
    const epoch = this.epoch;
    const s = await this.state();
    this.assertEpoch(epoch);
    if (!s.release || s.boot !== this.boot || !['INSTALLED', 'ACTIVE'].includes(s.state))
      deny('PROBE_STATE');
    const release = s.release;
    source = structuredClone(source);
    if (
      sha(source.files) !== release.sourceDigest ||
      !release.files['scripts/publication_consumer_guard_entry.py'] ||
      !release.files['bridge_core/publication_consumer_enrollment.py']
    )
      deny('PROBE_SOURCE');
    for (const [p, v] of Object.entries(release.files)) await this.bytes(release.root, p, v);
    await this.bytes(
      path.dirname(source.python.path),
      path.basename(source.python.path),
      source.python.sha256,
    );
    this.ownerCurrent();
    if (this.epoch !== epoch) deny('REVOKED');
    const nonce = hash(randomUUID());
    const program =
      "import sys,runpy;sys.path.insert(0,sys.argv[1]);sys.argv=['publication_consumer_guard_entry','--entry',sys.argv[2],'--probe','--nonce',sys.argv[3],'--generation',sys.argv[4]];runpy.run_module('scripts.publication_consumer_guard_entry',run_name='__main__')";
    const data = await new Promise<Buffer>((resolve, reject) => {
      const child = spawn(
        source.python.path,
        ['-I', '-c', program, release.root, entryId, nonce, release.generation],
        {
          cwd: release.root,
          env: { PATH: '/usr/bin:/bin', LANG: 'en_US.UTF-8', PYTHONDONTWRITEBYTECODE: '1' },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let done = false,
        size = 0;
      const parts: Buffer[] = [];
      const timer = setTimeout(() => finish(Error('PUBLICATION_MANAGED_PROBE_TIMEOUT')), 10000);
      const finish = (error?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (error) {
          child.kill('SIGTERM');
          reject(error);
        } else resolve(Buffer.concat(parts));
      };
      child.stdout.on('data', (b: Buffer) => {
        size += b.length;
        if (size > 65536) finish(Error('PUBLICATION_MANAGED_PROBE_LIMIT'));
        else parts.push(b);
      });
      child.stderr.resume();
      child.on('error', finish);
      child.on('close', (c) =>
        finish(c === 0 ? undefined : Error('PUBLICATION_MANAGED_PROBE_UNKNOWN')),
      );
    });
    this.ownerCurrent();
    if (this.epoch !== epoch) deny('REVOKED');
    let value: {
      schema: string;
      entryId: string;
      nonce: string;
      generation: string;
      files: Record<string, string>;
      nativeWithoutMain: string;
      businessEffects: number;
      inventory: unknown;
    };
    try {
      value = JSON.parse(data.toString('utf8'));
    } catch {
      deny('PROBE_SCHEMA');
    }
    if (
      value!.schema !== 'publication-enrollment-probe/v1' ||
      value!.entryId !== entryId ||
      value!.nonce !== nonce ||
      value!.generation !== release.generation ||
      value!.nativeWithoutMain !== 'DENIED' ||
      value!.businessEffects !== 0 ||
      !value!.files ||
      !Object.keys(value!.files).length
    )
      deny('PROBE_BINDING');
    for (const [p, v] of Object.entries(value!.files))
      if (release.files[p] !== v) deny('PROBE_SOURCE');
    for (const [p, v] of Object.entries(release.files)) await this.bytes(release.root, p, v);
    if (this.epoch !== epoch) deny('REVOKED');
    const observation: ManagedEnrollmentObservation = {
      accountScopeRef: this.accountScopeRef,
      deviceScopeRef: this.deviceScopeRef,
      boot: this.boot,
      generation: release.generation,
      root: release.root,
      sourceDigest: release.sourceDigest,
      entryId,
      nonce,
      files: value!.files,
      nativeWithoutMain: 'DENIED',
      inventoryDigest: canonicalDigest(value!.inventory),
    };
    const key = sha(['publication-loaded-guard/v1', this.boot, release.generation, entryId, nonce]);
    if (
      !(await this.store.compareAndSwapConsumerGuardReceipt(
        this.plugin,
        this.accountScopeRef,
        key,
        undefined,
        JSON.stringify(observation),
      ))
    )
      deny('CAS');
    this.ownerCurrent();
    if (this.epoch !== epoch) deny('REVOKED');
    const handle = Object.freeze(Object.create(null));
    lifecycleReceipts.set(handle, { owner: this, epoch, state: s.state, value: structuredClone(observation) });
    if (entryId === 'canonical-producer' && s.state === 'ACTIVE') {
      await this.exclusive(async () => {
        this.assertEpoch(epoch);
        const current = await this.state();
        this.assertEpoch(epoch);
        this.assertCurrent(release.root);
        if (current.state !== 'ACTIVE' || sha(current.release) !== sha(release)) deny('LEDGER_DRIFT');
        const loaded: Lifecycle = {
          ...current, sequence: current.sequence + 1,
          sourcePhase: 'LOADED', lifecycleSequence: current.lifecycleSequence + 1,
        };
        await this.write(loaded, epoch);
        this.completeLifecycle('LOADED', loaded, epoch, handle);
      });
    }
    return handle;
  }
  /** Actual closed launcher negative control for this installed owned realm only.
   * Foreign/CI/old deployments need their own source receipt and cannot use this handle. */
  async namespaceFence(source: PublisherReleaseSource, namespace: string): Promise<object> {
    if (
      ![
        'bulk-report-sync',
        'reserved-bundle',
        'private-report-files',
        'external-subtree-publishers',
      ].includes(namespace)
    )
      deny('NAMESPACE');
    const before = await this.coverageSourceState();
    if (before.state.state !== 'ACTIVE' || !before.state.release) deny('NAMESPACE_STATE');
    let denied = false;
    try {
      await this.prepareOwnedChild(Object.create(null), source, {
        operation: 'namespace:' + namespace,
      } as never);
    } catch (e) {
      denied = e instanceof Error && e.message === 'PUBLICATION_MANAGED_LAUNCH';
    }
    if (!denied) deny('NAMESPACE_NEGATIVE_CONTROL');
    const loaded = readManagedEnrollmentReceipt(
      await this.probeEnrollment(source, 'owned-namespace-source'),
      this,
    );
    this.assertCurrent(before.state.release.root);
    if (before.epoch !== this.epoch) deny('REVOKED');
    const value: ManagedEnrollmentObservation = {
      ...loaded,
      entryId: 'namespace:' + namespace,
      nonce: hash(randomUUID()),
    };
    const key = sha([
      'publication-owned-namespace-fence/v1',
      this.boot,
      this.epoch,
      namespace,
      value.nonce,
    ]);
    if (
      !(await this.store.compareAndSwapConsumerGuardReceipt(
        this.plugin,
        this.accountScopeRef,
        key,
        undefined,
        JSON.stringify({ ...value, scope: 'OWNED_LAUNCHER_ONLY' }),
      ))
    )
      deny('CAS');
    this.assertCurrent(value.root);
    if (before.epoch !== this.epoch) deny('REVOKED');
    const handle = Object.freeze(Object.create(null));
    lifecycleReceipts.set(handle, { owner: this, epoch: this.epoch, state: 'ACTIVE', value });
    return handle;
  }
  /** The synchronous owner identity used by the Main source broker. */
  currentSourceBinding(): ManagedSourceBinding {
    this.ownerCurrent();
    if (this.closed || !this.release) deny('REVOKED');
    return {
      accountId: this.accountScopeRef,
      deviceId: this.deviceScopeRef,
      bootId: this.boot,
      ownerEpoch: this.epoch,
      generation: this.release.generation,
    };
  }
  lifecycleReceiptCurrent(epoch: number, value: ManagedLifecycleObservation): boolean {
    this.ownerCurrent();
    return this.epoch === epoch && this.completedLifecycle?.epoch === epoch &&
      this.completedLifecycle.phase === value.phase &&
      this.release?.root === value.root &&
      this.release.generation === value.binding.generation &&
      this.releaseSequenceFloor === value.releaseSequence &&
      this.lifecycleSequenceFloor === value.lifecycleSequence &&
      (!['ENTRY_SWITCHED', 'LOADED'].includes(value.phase) || !this.closed);
  }
  /** Project only a completed original operation, never a requested phase or supplied JSON. */
  async produceLifecycle(
    phase: ManagedLifecyclePhase,
    enrollmentHandle?: object,
  ): Promise<object> {
    const epoch = this.epoch;
    return this.exclusive(async () => {
      this.assertEpoch(epoch);
      const proof = this.completedLifecycle;
      if (!proof || proof.epoch !== epoch || proof.phase !== phase) deny('LIFECYCLE_PHASE');
      const state = await this.state(epoch);
      this.assertEpoch(epoch);
      const release = state.release;
      if (
        state.boot !== this.boot || !release || !state.operationId ||
        state.sourcePhase !== phase || sha(state) !== proof.stateDigest ||
        sha(this.release) !== sha(release) ||
        (phase === 'INSTALLED' && state.state !== 'INSTALLED') ||
        (['ENTRY_SWITCHED', 'LOADED'].includes(phase) && (state.state !== 'ACTIVE' || this.closed)) ||
        (['REVOKED', 'DRAINED'].includes(phase) && state.state !== 'REVOKED')
      ) deny('LIFECYCLE_STATE');
      let enrollment: ManagedEnrollmentObservation | null = null;
      if (phase === 'LOADED') {
        enrollmentHandle ??= proof.enrollment;
        const enrolled = enrollmentHandle && lifecycleReceipts.get(enrollmentHandle);
        if (
          !enrolled || enrollmentHandle !== proof.enrollment || enrolled.owner !== this ||
          enrolled.epoch !== epoch || enrolled.state !== 'ACTIVE' ||
          enrolled.value.entryId !== 'canonical-producer'
        ) deny('LIFECYCLE_ENROLLMENT');
        enrollment = readManagedEnrollmentReceipt(enrollmentHandle!, this);
        if (
          enrollment.generation !== release.generation || enrollment.root !== release.root ||
          enrollment.sourceDigest !== release.sourceDigest ||
          enrollment.accountScopeRef !== this.accountScopeRef ||
          enrollment.deviceScopeRef !== this.deviceScopeRef || enrollment.boot !== this.boot
        ) deny('LIFECYCLE_ENROLLMENT');
      } else if (enrollmentHandle !== undefined) deny('LIFECYCLE_ENROLLMENT');
      if (proof.receipt) {
        await this.verifyLifecycleReceipt(proof.receipt);
        return proof.receipt;
      }
      const [unresolvedAdmissions, unknownNativeEffects] = await Promise.all([
        this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.accountScopeRef),
        this.store.unknownNativePublicationEffects(this.plugin),
      ]);
      this.assertEpoch(epoch);
      if (![unresolvedAdmissions, unknownNativeEffects].every(
        (value) => Number.isSafeInteger(value) && value >= 0,
      )) deny('LIFECYCLE_COUNTS');
      const value: ManagedLifecycleObservation = {
        schema: 'publication-main-lifecycle-source/v1',
        scope: 'OWNED_CONTROLLER_ONLY',
        operationId: state.operationId,
        binding: {
          accountId: this.accountScopeRef, deviceId: this.deviceScopeRef, bootId: this.boot,
          ownerEpoch: epoch, generation: release.generation,
        },
        phase, releaseSequence: state.releaseSequence, lifecycleSequence: state.lifecycleSequence,
        root: release.root, sourceDigest: release.sourceDigest, files: { ...release.files },
        enrollment, ownedJobs: this.jobs.size, unresolvedAdmissions, unknownNativeEffects,
      };
      const key = sha(['publication-main-lifecycle-source/v1', this.boot,
        state.operationId, state.releaseSequence, state.lifecycleSequence, phase]);
      const payload = JSON.stringify(value);
      if (!(await this.store.compareAndSwapConsumerGuardReceipt(
        this.plugin, this.accountScopeRef, key, undefined, payload,
      ))) deny('LIFECYCLE_REPLAY');
      this.assertEpoch(epoch);
      const handle = Object.freeze(Object.create(null));
      managedLifecycleReceipts.set(handle, {
        owner: this, epoch, stateDigest: proof.stateDigest, key,
        row: { revision: 1, payload }, value: structuredClone(value),
      });
      proof.receipt = handle;
      return handle;
    });
  }
  /** Recheck the original account receipt and release state without renewing or issuing anything. */
  async verifyLifecycleReceipt(handle: object): Promise<Readonly<ManagedLifecycleObservation>> {
    const receipt = managedLifecycleReceipts.get(handle);
    if (!receipt || receipt.owner !== this) deny('LIFECYCLE_RECEIPT');
    const epoch = receipt.epoch;
    try {
      const value = readManagedLifecycleReceipt(handle, this);
      const state = await this.state(epoch);
      this.assertEpoch(epoch);
      if (sha(state) !== receipt.stateDigest || sha(state.release) !== sha(this.release))
        deny('LIFECYCLE_LEDGER_DRIFT');
      const row = await this.store.readConsumerGuardReceipt(this.plugin, this.accountScopeRef, receipt.key);
      this.assertEpoch(epoch);
      if (!row || row.revision !== receipt.row.revision || row.payload !== receipt.row.payload)
        deny('LIFECYCLE_LEDGER_DRIFT');
      readManagedLifecycleReceipt(handle, this);
      return value;
    } catch (error) {
      if (epoch === this.epoch) this.invalidate();
      throw error;
    }
  }
  receiptCurrent(epoch: number, root: string): boolean {
    this.ownerCurrent();
    return this.epoch === epoch && this.release?.root === root;
  }
  /** Fixed owned lifecycle identity; counts are measured from the original account ledger. */
  async coverageSourceState() {
    const epoch = this.epoch;
    const state = await this.state(epoch);
    const [unresolved, unknownNativeEffects] = await Promise.all([
      this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.accountScopeRef),
      this.store.unknownNativePublicationEffects(this.plugin),
    ]);
    this.assertEpoch(epoch);
    return {
      state, epoch, boot: this.boot, ownedJobs: this.jobs.size,
      unresolved, unknownNativeEffects,
    };
  }
  /** Source-owned lifecycle fact only; never manufactures missing real legacy/CI/namespace data. */
  async inspect() {
    const s = await this.state();
    return {
      ...s,
      ownedJobs: this.jobs.size,
      runtimeCoverage: 'UNKNOWN' as const,
      missingOperationalInputs: [
        'legacy-writer-enrollment',
        'worksheet-CI-and-resident-fences',
        'retirement-and-adjacent-namespace-receipts',
      ],
    };
  }
}
