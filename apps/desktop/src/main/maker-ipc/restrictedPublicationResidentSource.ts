/** Main's held, kernel-authenticated original-entry listener.
 * Expected descriptors are not census evidence. Only accepted original peers
 * can create a receipt, and C independently binds resident peers to the OS.
 * CI runner effects use separate one-use Main capabilities persisted before
 * transmission; all original publication/namespace scopes remain non-releasing.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { Readable, Writable } from 'node:stream';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import { readPublicationHistoryReceipt } from './restrictedPartnerStore.js';
import type { PublicationSourceBinding } from './restrictedPublicationCISourceBroker.js';
import { canonical, digest, parseNativeFrame } from './restrictedPublicationProtocol.js';
import { ManagedPublicationController } from './restrictedPublicationManagedController.js';
import { verifyOriginalRetirementReceipt, type RestrictedPublicationOwnerRegistry } from './restrictedPublicationOwnerRegistry.js';
import { consumeOriginalCIEffectPermit, validateOriginalCIEffect,
  type OriginalCIEffectObservation } from './restrictedPublicationCIProducer.js';

const SCHEMA = 'resident-owner-listener/v1';
const ENTRY = 'bridge_core/publication_owner_listener.py';
const FRAME = 65536;
const TOTAL = 1048576;
const TTL = 60000;
const hash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const opaque = (v: unknown): v is string => typeof v === 'string' && v.length > 0 &&
  Buffer.byteLength(v) <= 512 && !/[\u0000-\u001f\u007f-\u009f]/.test(v);
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
function fail(code: string): never { throw Error('PUBLICATION_RESIDENT_SOURCE_' + code); }
function exact(value: unknown, names: string): asserts value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== names.split(',').sort().join(',')) fail('SCHEMA');
}
function relative(value: string) {
  return opaque(value) && !path.isAbsolute(value) && !value.includes('\\') &&
    value.split('/').every(p => p && p !== '.' && p !== '..');
}
function binding(value: PublicationSourceBinding) {
  exact(value, 'accountId,deviceId,bootId,ownerEpoch,generation');
  if (!hash(value.accountId) || !hash(value.deviceId) || !opaque(value.bootId) ||
      !opaque(value.generation) || !count(value.ownerEpoch)) fail('BINDING');
  return structuredClone(value);
}
export type OriginalOwnerScope = 'RESIDENT_ORIGINAL_ENTRY' | 'REGISTERED_NAMESPACE_OWNER' |
  'REGISTERED_RESIDENT_NONPUBLISHER' | 'REGISTERED_CI_PRODUCER';
const ciOriginalEntries: Readonly<Record<string, { role: string; entry: string }>> = {
  'core-jit.persistent-bridge-pool': { role: 'persistent-pool', entry: 'macmini-jit-controller/sync-runner-pools.py' },
  'core-jit.bridge-jit-controller': { role: 'jit-controller', entry: 'macmini-jit-controller/start-approved-jit-runner.sh' },
  'core-jit.bridge-jit-dispatcher': { role: 'jit-dispatcher', entry: 'macmini-jit-controller/jit-deploy-dispatcher.sh' },
};
export interface OriginalPublicationOwnerDescriptor {
  instanceId: string;
  ownerId: string;
  sourceScope: OriginalOwnerScope;
  entryScript: string;
  originalEntryScript: string;
  originalRoot: string;
  originalArgv: string[];
  entryArgv: string[];
  originalBootstrapSha256: string;
  definitionDigest: string;
}
export interface PinnedPublicationResidentSource {
  root: string;
  files: Readonly<Record<string, string>>;
  python: { path: string; sha256: string };
  sourceDigest: string;
  runtimeDirectory: string;
  owners: ReadonlyArray<OriginalPublicationOwnerDescriptor>;
}
/** Source/target metadata only. Runtime copies keep their real paths while
 * their bytes and adjacent helper remain bound to fixed canonical release pins. */
export function originalCIProducerBootstrap(owner: OriginalPublicationOwnerDescriptor,
  files: Readonly<Record<string, string>>) {
  const source = Object.hasOwn(ciOriginalEntries, owner.ownerId) ? ciOriginalEntries[owner.ownerId] : undefined;
  const sourceHelper = 'macmini-jit-controller/publication_ci_owner.py';
  if (owner.sourceScope !== 'REGISTERED_CI_PRODUCER' || !source ||
      owner.entryScript !== 'bridge_core/publication_ci_producer.py' ||
      !relative(owner.originalEntryScript) || path.basename(owner.originalEntryScript) !== path.basename(source.entry) ||
      !files || files[source.entry] !== owner.originalBootstrapSha256 || !hash(owner.originalBootstrapSha256) ||
      !hash(files[sourceHelper]) || !hash(files[owner.entryScript]) ||
      !Array.isArray(owner.originalArgv) || owner.originalArgv.length < 2 ||
      path.resolve(owner.originalRoot, owner.originalArgv[1]) !== path.join(owner.originalRoot, owner.originalEntryScript) ||
      !Array.isArray(owner.entryArgv) || canonical(owner.entryArgv.slice(4)) !==
        canonical([source.role, ...owner.originalArgv.slice(2)])) fail('PROFILE');
  return { sourceEntry: source.entry, sourceHelper,
    runtimeHelper: path.join(path.dirname(owner.originalEntryScript), 'publication_ci_owner.py') };
}
type Phase = 'CONNECTED' | 'LOADED' | 'RUNNING' | 'FINISHED' | 'FENCED' | 'DRAINED' | 'RETIRED' | 'UNKNOWN';
export interface OriginalPublicationPeerObservation {
  peerId: string;
  instanceId: string;
  ownerId: string;
  sourceScope: OriginalOwnerScope;
  entryScript: string;
  originalEntryScript: string;
  root: string;
  sourceDigest: string;
  definitionDigest: string;
  process: { processId: number; uid: number; startIdentity: string; executable: string; argv: string[]; cwd: string };
  files: Record<string, string>;
  observation: { state: Phase; loadedNonce: string | null; nativeWithoutMain: 'DENIED' | null;
    activeOperations: number; unknownOperations: number; fenceRevision: number;
    probe: Record<string, unknown> | null; ciEffect?: OriginalCIEffectObservation | null };
}
type Store = Pick<ReturnType<typeof createRestrictedPartnerStore>,
  'consumerGuardReceiptIdentity' | 'readConsumerGuardReceipt' | 'compareAndSwapConsumerGuardReceipt' |
  'capturePublicationOwnerHistory' | 'assertPublicationOwnerHistoryCurrent' |
  'unresolvedConsumerGuardAdmissions' | 'unknownNativePublicationEffects'>;
type Row = Awaited<ReturnType<Store['readConsumerGuardReceipt']>>;
type PeerRecord = { instanceId: string; peerId: string; identity: string; phase: Phase | 'FENCING' | 'DRAINING' | 'RETIRING';
  originalBootstrapSha256: string; definitionDigest: string; revision: number; observation: OriginalPublicationPeerObservation };
type Ledger = { schema: 'publication-original-owner-listener/v1'; scope: 'ORIGINAL_PEERS_ONLY';
  operationId: string; binding: PublicationSourceBinding; profileSha256: string;
  runtimeDirectory: string;
  state: 'STARTING' | 'OPEN' | 'CUTOVER_HELD' | 'ROTATING_UNKNOWN' | 'POLICY_PREPARED' | 'UNKNOWN' | 'REVOKED';
  listenerPid: number | null; peers: PeerRecord[];
  preparedPolicy?: { previousPolicySha256: string; nextPolicySha256: string; revision: number } };
type Pin = { file: string; sha256: string; identity: string; maximum: number };
const identity = (s: Awaited<ReturnType<typeof lstat>>) =>
  [s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs].join(':');
async function pinned(file: string, expected: string, maximum: number) {
  if (!hash(expected) || !path.isAbsolute(file) || path.normalize(file) !== file || await realpath(file) !== file)
    fail('PIN');
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
      (before.mode & 0o022) || before.size > maximum) fail('PIN');
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (identity(await fd.stat()) !== identity(before)) fail('SOURCE_CHANGED');
    const bytes = await fd.readFile();
    if (bytes.length !== before.size || createHash('sha256').update(bytes).digest('hex') !== expected ||
        identity(await fd.stat()) !== identity(before) || identity(await lstat(file)) !== identity(before) ||
        await realpath(file) !== file) fail('SOURCE_CHANGED');
    return { identity: identity(before), size: bytes.length };
  } finally { await fd.close(); }
}
const owners = new WeakSet<object>();
const receipts = new WeakMap<object, { owner: RestrictedPublicationResidentSource; peerId: string;
  revision: number; value: OriginalPublicationPeerObservation }>();
type RetainedCutover = { owner: RestrictedPublicationResidentSource; controller: ManagedPublicationController;
  binding: PublicationSourceBinding; row: NonNullable<Row>; peerIds: string[];
  policyRevision: number; policySha256: string; consumed: boolean };
const cutovers = new WeakMap<object, RetainedCutover>();
export function isOriginalPublicationSource(value: unknown): value is RestrictedPublicationResidentSource {
  return !!value && typeof value === 'object' && owners.has(value);
}
export function readOriginalPublicationPeerReceipt(handle: object, owner: RestrictedPublicationResidentSource) {
  const r = receipts.get(handle);
  if (!r || r.owner !== owner || !owners.has(owner)) fail('PRIVATE_RECEIPT_REQUIRED');
  owner.assertPeerRevision(r.peerId, r.revision);
  return structuredClone(r.value);
}

export class RestrictedPublicationResidentSource {
  private readonly profile: PinnedPublicationResidentSource;
  private readonly expected: PublicationSourceBinding;
  private readonly sessionId = randomBytes(32).toString('hex');
  private readonly started = performance.now();
  private readonly key: string;
  private readonly pins: Pin[] = [];
  private readonly directories = new Map<string, string>();
  private ledger: Ledger;
  private row: Row;
  private child?: ChildProcess;
  private childExit?: Promise<void>;
  private childExitCode: number | null = null;
  private childClosed = false;
  private responseEOF = false;
  private closed = false;
  private busy = false;
  private closing?: Promise<void>;
  private deadline?: ReturnType<typeof setTimeout>;
  private sequence = -1;
  private nextNonce = randomBytes(32).toString('hex');
  private policyRevision?: number;
  private policySha256?: string;
  private retainedCutover?: object;
  private terminalExpected = false;
  private terminalFrameReceived = false;
  private buffer = Buffer.alloc(0);
  private inputBytes = 0;
  private outputBytes = 0;
  private pending?: { seq: number; terminal: boolean; timer: ReturnType<typeof setTimeout>;
    resolve: (value: Record<string, any>) => void; reject: (error: Error) => void };
  private constructor(private readonly store: Store, private readonly plugin: string,
    readonly operationId: string, profile: PinnedPublicationResidentSource,
    expected: PublicationSourceBinding, private readonly currentBinding: () => PublicationSourceBinding) {
    this.expected = binding(expected);
    exact(profile, 'root,files,python,sourceDigest,runtimeDirectory,owners');
    exact(profile.python, 'path,sha256');
    if (!opaque(plugin) || !opaque(operationId) || !hash(profile.sourceDigest) ||
        !path.isAbsolute(profile.runtimeDirectory) || path.normalize(profile.runtimeDirectory) !== profile.runtimeDirectory ||
        !Array.isArray(profile.owners) || !profile.owners.length || profile.owners.length > 64) fail('PROFILE');
    const ids = new Set<string>();
    for (const o of profile.owners) {
      exact(o, 'instanceId,ownerId,sourceScope,entryScript,originalEntryScript,originalRoot,originalArgv,entryArgv,originalBootstrapSha256,definitionDigest');
      if (!opaque(o.instanceId) || ids.has(o.instanceId) || !opaque(o.ownerId) ||
          !['RESIDENT_ORIGINAL_ENTRY', 'REGISTERED_NAMESPACE_OWNER', 'REGISTERED_RESIDENT_NONPUBLISHER',
            'REGISTERED_CI_PRODUCER'].includes(o.sourceScope) ||
          !relative(o.entryScript) || !relative(o.originalEntryScript) || !hash(o.originalBootstrapSha256) ||
          !hash(o.definitionDigest) || !path.isAbsolute(o.originalRoot) ||
          path.normalize(o.originalRoot) !== o.originalRoot || !Array.isArray(o.originalArgv) ||
          !o.originalArgv.length || o.originalArgv.length > 64 || !o.originalArgv.every(opaque) ||
          !Array.isArray(o.entryArgv) || o.entryArgv.length < 4 || o.entryArgv.length > 64 ||
          !o.entryArgv.every(opaque) || canonical(o.entryArgv.slice(0, 4)) !==
            canonical([profile.python.path, '-I', '-B', path.join(profile.root, o.entryScript)])) fail('PROFILE');
      if (o.sourceScope === 'REGISTERED_CI_PRODUCER')
        originalCIProducerBootstrap(o as OriginalPublicationOwnerDescriptor, profile.files);
      ids.add(o.instanceId);
    }
    this.profile = structuredClone(profile);
    this.key = digest(['publication-original-owner-listener/v1', expected.deviceId, operationId,
      profile.runtimeDirectory]);
    this.ledger = { schema: 'publication-original-owner-listener/v1', scope: 'ORIGINAL_PEERS_ONLY',
      operationId, binding: this.expected, profileSha256: digest(this.profile), runtimeDirectory: profile.runtimeDirectory,
      state: 'STARTING', listenerPid: null, peers: [] };
    owners.add(this);
  }
  static async startOwned(store: Store, plugin: string, operationId: string,
    profile: PinnedPublicationResidentSource, expected: PublicationSourceBinding,
    currentBinding: () => PublicationSourceBinding) {
    const self = new RestrictedPublicationResidentSource(store, plugin, operationId, profile, expected, currentBinding);
    self.assertCurrent();
    if (await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key)) fail('OPERATION_ALREADY_CLAIMED');
    for (const descriptor of profile.owners) {
      const key = digest(['publication-original-instance-claim/v1', expected.deviceId, descriptor.instanceId]);
      if (await store.readConsumerGuardReceipt(plugin, expected.accountId, key)) fail('INSTANCE_ALREADY_CLAIMED');
    }
    const priorHistory = await store.capturePublicationOwnerHistory(plugin, expected.accountId);
    const prior = readPublicationHistoryReceipt(priorHistory, store.consumerGuardReceiptIdentity, plugin, expected.accountId);
    for (const row of prior.rows) {
      const value = JSON.parse(row.payload) as Record<string, unknown>;
      if (value.schema === 'publication-original-owner-listener/v1' &&
          (value.runtimeDirectory === profile.runtimeDirectory || value.runtimeDirectory === undefined) &&
          ['UNKNOWN', 'ROTATING_UNKNOWN', 'CUTOVER_HELD'].includes(String(value.state)))
        fail('PRIOR_POLICY_CUTOVER_UNKNOWN');
      if ((value.schema === 'publication-original-policy-cutover/v1' ||
           value.schema === 'publication-managed-prepared-install/v1') && value.state !== 'COMMITTED')
        fail('PRIOR_POLICY_CUTOVER_UNKNOWN');
    }
    await store.assertPublicationOwnerHistoryCurrent(priorHistory, plugin, expected.accountId);
    if (await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key) ||
        !await store.compareAndSwapConsumerGuardReceipt(plugin, expected.accountId, self.key, undefined, self.payload()))
      fail('OPERATION_ALREADY_CLAIMED');
    try {
      self.row = await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key);
      if (!self.row || self.row.revision !== 1 || self.row.payload !== self.payload()) fail('LEDGER_CHANGED');
      // A planned instance is consumed before opening a listener, even if its
      // source pin later fails. These rows are claims, never observed members.
      // A replacement boot/generation/operation cannot replay UNKNOWN by giving
      // the same original instance a fresh listener operation ID.
      for (const descriptor of profile.owners) {
        const key = digest(['publication-original-instance-claim/v1', expected.deviceId, descriptor.instanceId]);
        const claim = canonical({ schema: 'publication-original-instance-claim/v1', scope: 'EXPECTED_INSTANCE_ONLY',
          instanceId: descriptor.instanceId, operationId, binding: self.expected,
          listenerKey: self.key, descriptorSha256: digest(descriptor) });
        if (await store.readConsumerGuardReceipt(plugin, expected.accountId, key) ||
            !await store.compareAndSwapConsumerGuardReceipt(plugin, expected.accountId, key, undefined, claim))
          fail('INSTANCE_ALREADY_CLAIMED');
      }
      await self.capturePins();
      // The exact original account snapshot is rechecked after claiming all
      // instances. A new operation/generation cannot race an earlier UNKNOWN
      // or an incomplete multi-realm policy change into another source launch.
      const launchHistory = await store.capturePublicationOwnerHistory(plugin, expected.accountId);
      const launchRows = readPublicationHistoryReceipt(launchHistory, store.consumerGuardReceiptIdentity, plugin, expected.accountId);
      for (const row of launchRows.rows) {
        const value = JSON.parse(row.payload) as Record<string, unknown>;
        if (((value.schema === 'publication-original-policy-cutover/v1' ||
              value.schema === 'publication-managed-prepared-install/v1') && value.state !== 'COMMITTED') ||
            (value.schema === 'publication-original-owner-listener/v1' &&
              (value.runtimeDirectory === profile.runtimeDirectory || value.runtimeDirectory === undefined) &&
              ['UNKNOWN', 'ROTATING_UNKNOWN', 'CUTOVER_HELD'].includes(String(value.state))))
          fail('PRIOR_POLICY_CUTOVER_UNKNOWN');
      }
      if (!await store.compareAndSwapConsumerGuardReceipt(plugin, expected.accountId, self.key,
          self.row, self.payload(), true, launchHistory)) fail('LEDGER_CHANGED');
      self.row = { revision: self.row.revision + 1, payload: self.payload() };
      self.launch();
      const p = self.profile;
      const result = await self.exchange({ schema: SCHEMA, sessionId: self.sessionId, operationId,
        binding: self.expected, runtimeDirectory: p.runtimeDirectory, sourceRoot: p.root,
        sourceDigest: p.sourceDigest, sourceFiles: p.files, resolvedInterpreter: p.python.path,
        interpreterSha256: p.python.sha256, owners: p.owners, expiresAt: Date.now() + TTL - 1000,
        nonce: self.nextNonce }, 0);
      self.listenerResult(result);
      self.ledger.state = 'OPEN';
      self.ledger.listenerPid = self.child!.pid!;
      await self.save();
      return self;
    } catch (error) { await self.terminate('UNKNOWN'); throw error; }
  }
  private async capturePins() {
    const p = this.profile;
    if (!p.files || !Object.keys(p.files).length || Object.keys(p.files).length > 256 ||
        ![ENTRY, 'bridge_core/publication_resident_source.py', ...p.owners.map(owner => owner.entryScript)]
          .every(name => hash(p.files[name])) || !path.isAbsolute(p.root) ||
        await realpath(p.root) !== p.root || !(await lstat(p.root)).isDirectory()) fail('SOURCE_PROFILE');
    let total = 0;
    const add = async (file: string, sha256: string, maximum: number) => {
      const x = await pinned(file, sha256, maximum);
      this.pins.push({ file, sha256, maximum, identity: x.identity });
      let parent = path.dirname(file);
      while (true) {
        const st = await lstat(parent);
        if (!st.isDirectory() || st.isSymbolicLink() ||
            ((st.mode & 0o022) && !((st.mode & 0o1000) && st.uid === 0))) fail('PIN_DIRECTORY');
        const key = [st.dev, st.ino, st.mode].join(':');
        const old = this.directories.get(parent);
        if (old !== undefined && old !== key) fail('SOURCE_CHANGED');
        this.directories.set(parent, key);
        const next = path.dirname(parent);
        if (next === parent) break;
        parent = next;
      }
      return x.size;
    };
    for (const [name, sha256] of Object.entries(p.files)) {
      if (!relative(name)) fail('SOURCE_PROFILE');
      total += await add(path.join(p.root, name), sha256, 4 * TOTAL);
      if (total > 64 * TOTAL) fail('SOURCE_BUDGET');
    }
    await add(p.python.path, p.python.sha256, 128 * TOTAL);
    for (const o of p.owners) {
      await add(path.join(o.originalRoot, o.originalEntryScript), o.originalBootstrapSha256, 4 * TOTAL);
      if (o.sourceScope === 'REGISTERED_CI_PRODUCER') {
        const ci = originalCIProducerBootstrap(o, p.files);
        await add(path.join(o.originalRoot, ci.runtimeHelper), p.files[ci.sourceHelper], 4 * TOTAL);
      }
    }
  }
  private async verifyPinnedFiles() {
    for (const [file, expected] of this.directories) {
      const s = await lstat(file);
      if (!s.isDirectory() || s.isSymbolicLink() || [s.dev, s.ino, s.mode].join(':') !== expected) fail('SOURCE_CHANGED');
    }
    for (const p of this.pins) if ((await pinned(p.file, p.sha256, p.maximum)).identity !== p.identity) fail('SOURCE_CHANGED');
  }
  private async verifyPins() {
    this.assertCurrent();
    await this.verifyPinnedFiles();
    this.assertCurrent();
  }
  assertCurrent() {
    if (this.retainedCutover || this.closed || this.childClosed || performance.now() - this.started >= TTL ||
        canonical(binding(this.currentBinding())) !== canonical(this.expected)) fail('CLOSED');
  }
  assertPeerRevision(peerId: string, revision: number) {
    this.assertCurrent();
    const peer = this.ledger.peers.find(x => x.peerId === peerId);
    if (!peer || peer.revision !== revision || ['UNKNOWN', 'FENCING', 'DRAINING', 'RETIRING'].includes(peer.phase))
      fail('STALE_PEER_RECEIPT');
  }
  private launch() {
    this.assertCurrent();
    const child = this.child = spawn(this.profile.python.path,
      ['-I', '-B', path.join(this.profile.root, ENTRY), '--publication-owner-listener'], {
        cwd: this.profile.root, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' },
        stdio: Array.from({ length: 15 }, (_, i) => i === 13 || i === 14 ? 'pipe' : 'ignore'),
      });
    this.childExit = new Promise(resolve => child.once('close', code => {
      this.childExitCode = code; this.childClosed = true; resolve();
    }));
    child.once('error', () => this.rejectPending('CHILD_FAILED'));
    child.once('close', () => {
      if (!this.closed && !(this.terminalExpected && this.terminalFrameReceived)) this.rejectPending('CHILD_CLOSED');
    });
    const descriptors: ReadonlyArray<Readable | Writable | null | undefined> = child.stdio;
    const input = descriptors[14];
    if (!input || !('read' in input)) fail('TRANSPORT');
    this.output();
    input.on('data', (chunk: Buffer) => this.receive(chunk));
    input.once('end', () => { this.responseEOF = true; });
    input.once('error', () => this.rejectPending('RESPONSE_STREAM_FAILED'));
    input.once('close', () => {
      if (!this.closed && !this.responseEOF) this.rejectPending('RESPONSE_EOF_UNKNOWN');
    });
    this.deadline = setTimeout(() => { void this.terminate('UNKNOWN'); }, TTL);
  }
  private rejectPending(code: string) {
    const pending = this.pending;
    this.pending = undefined;
    if (pending) { clearTimeout(pending.timer); pending.reject(Error('PUBLICATION_RESIDENT_SOURCE_' + code)); }
    void this.terminate('UNKNOWN');
  }
  private receive(chunk: Buffer) {
    try {
      this.inputBytes += chunk.length;
      if (this.inputBytes > TOTAL) fail('FRAME_LIMIT');
      this.buffer = Buffer.concat([this.buffer, chunk]);
      const newline = this.buffer.indexOf(10);
      if (newline < 0) { if (this.buffer.length > FRAME) fail('FRAME_LIMIT'); return; }
      if (newline + 1 !== this.buffer.length || newline >= FRAME || !this.pending) fail('UNEXPECTED_FRAME');
      const frame = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(this.buffer.subarray(0, newline)));
      this.buffer = Buffer.alloc(0);
      exact(frame, 'schema,sessionId,operationId,binding,seq,nextNonce,ok,code,result');
      const p = this.pending;
      if (frame.schema !== SCHEMA || frame.sessionId !== this.sessionId || frame.operationId !== this.operationId ||
          canonical(frame.binding) !== canonical(this.expected) || frame.seq !== p.seq ||
          frame.ok !== true || frame.code !== null ||
          (p.terminal ? frame.nextNonce !== null : !hash(frame.nextNonce)) ||
          !frame.result || typeof frame.result !== 'object' || Array.isArray(frame.result)) fail('SOURCE_REFUSED');
      if (p.terminal) this.terminalFrameReceived = true;
      else this.nextNonce = frame.nextNonce;
      this.sequence = p.seq;
      this.pending = undefined;
      clearTimeout(p.timer);
      p.resolve(frame.result);
    } catch { this.rejectPending('FRAME_INVALID'); }
  }
  private async exchange(frame: Record<string, unknown>, seq: number, terminal = false) {
    if (!terminal) this.assertCurrent();
    else if (!this.retainedCutover || this.closed || this.childClosed || performance.now() - this.started >= TTL)
      fail('CUTOVER_CLOSED');
    if (this.pending || seq > 128) fail('SEQUENCE');
    const bytes = Buffer.from(canonical(frame) + '\n');
    if (bytes.length > FRAME || (this.outputBytes += bytes.length) > TOTAL) fail('FRAME_LIMIT');
    return new Promise<Record<string, any>>((resolve, reject) => {
      const timer = setTimeout(() => this.rejectPending('TIMEOUT'), 10000);
      this.pending = { seq, terminal, resolve, reject, timer };
      this.output().write(bytes, error => { if (error) this.rejectPending('WRITE_FAILED'); });
    });
  }
  private output(): Writable {
    const descriptors: ReadonlyArray<Readable | Writable | null | undefined> = this.child?.stdio ?? [];
    const stream = descriptors[13];
    if (!stream || !('write' in stream)) fail('TRANSPORT');
    return stream;
  }
  private async request(method: string, args: Record<string, unknown>) {
    await this.verifyPins();
    const result = await this.exchange({ schema: SCHEMA, sessionId: this.sessionId, operationId: this.operationId,
      binding: this.expected, seq: this.sequence + 1, nonce: this.nextNonce, method, args }, this.sequence + 1);
    await this.verifyPins();
    return result;
  }
  private listenerResult(value: Record<string, any>) {
    exact(value, 'state,processId,runtimeDirectory,sourceRoot,sourceDigest,peerCount,policyRevision,policySha256');
    if (value.processId !== this.child!.pid || value.runtimeDirectory !== this.profile.runtimeDirectory ||
        value.sourceRoot !== this.profile.root || value.sourceDigest !== this.profile.sourceDigest ||
        !count(value.peerCount) || value.peerCount > 64 || !count(value.policyRevision) ||
        !hash(value.policySha256) || value.state !== 'LISTENING') fail('LISTENER_BINDING');
    this.policyRevision = value.policyRevision;
    this.policySha256 = value.policySha256;
  }
  private peerResult(value: Record<string, any>, previous?: PeerRecord) {
    exact(value, 'peerId,instanceId,ownerId,sourceScope,entryScript,originalEntryScript,root,sourceDigest,definitionDigest,process,files,observation');
    exact(value.process, 'processId,uid,startIdentity,executable,argv,cwd');
    const ci = value.sourceScope === 'REGISTERED_CI_PRODUCER';
    exact(value.observation, 'state,loadedNonce,nativeWithoutMain,activeOperations,unknownOperations,fenceRevision,probe' +
      (ci ? ',ciEffect' : ''));
    const descriptor = this.profile.owners.find(x => x.instanceId === value.instanceId);
    if (!descriptor || !opaque(value.peerId) || value.root !== this.profile.root ||
        value.sourceDigest !== this.profile.sourceDigest || canonical(value.files) !== canonical(this.profile.files) ||
        !['instanceId', 'ownerId', 'sourceScope', 'entryScript', 'originalEntryScript', 'definitionDigest']
          .every(k => value[k] === descriptor[k as keyof OriginalPublicationOwnerDescriptor]) ||
        !count(value.process.processId) || value.process.processId === 0 || value.process.processId === this.child!.pid ||
        !count(value.process.uid) || !opaque(value.process.startIdentity) ||
        value.process.executable !== this.profile.python.path || !Array.isArray(value.process.argv) ||
        !value.process.argv.every(opaque) || canonical(value.process.argv) !== canonical(descriptor.entryArgv) ||
        value.process.cwd !== descriptor.originalRoot ||
        !['CONNECTED', 'LOADED', 'RUNNING', 'FINISHED', 'FENCED', 'DRAINED', 'RETIRED', 'UNKNOWN'].includes(value.observation.state) ||
        !count(value.observation.activeOperations) || !count(value.observation.unknownOperations) ||
        !count(value.observation.fenceRevision)) fail('PEER_BINDING');
    if (value.observation.state === 'CONNECTED') {
      // Kernel identity is observed before the original entry has loaded its
      // guard. Persist this phase without inventing a native denial proof.
      if (value.observation.nativeWithoutMain !== null || value.observation.loadedNonce !== null ||
          value.observation.probe !== null || value.observation.activeOperations !== 0 ||
          value.observation.unknownOperations !== 0 || value.observation.fenceRevision !== 0) fail('PEER_BINDING');
    } else if (value.observation.nativeWithoutMain !== 'DENIED' || !hash(value.observation.loadedNonce)) {
      fail('PEER_BINDING');
    }
    if (ci) {
      validateOriginalCIEffect(value.observation.ciEffect);
      if (value.observation.activeOperations > 1 || value.observation.unknownOperations > 1 ||
          (['CONNECTED', 'LOADED'].includes(value.observation.state) && value.observation.ciEffect !== null) ||
          (value.observation.state === 'RUNNING' && value.observation.activeOperations !== 1) ||
          (['FINISHED', 'FENCED', 'DRAINED', 'RETIRED'].includes(value.observation.state) &&
            (value.observation.activeOperations !== 0 || value.observation.unknownOperations !== 0 ||
             (value.observation.ciEffect !== null && value.observation.ciEffect.state !== 'ACKNOWLEDGED')))) fail('CI_PEER_BINDING');
    }
    const observed = structuredClone(value) as OriginalPublicationPeerObservation;
    if (previous && (previous.peerId !== observed.peerId || previous.instanceId !== observed.instanceId ||
        previous.identity !== digest(observed.process))) fail('PEER_CHANGED');
    return { descriptor, observed };
  }
  private async save(drained = false) {
    this.assertCurrent();
    const history = await this.store.capturePublicationOwnerHistory(this.plugin, this.expected.accountId);
    if (!this.row || !await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.expected.accountId,
        this.key, this.row, this.payload(), drained, history)) fail('LEDGER_CHANGED');
    const expected = { revision: this.row.revision + 1, payload: this.payload() };
    const actual = await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key);
    if (!actual || canonical(actual) !== canonical(expected)) fail('LEDGER_CHANGED');
    this.row = actual;
    this.assertCurrent();
  }
  /** Lossless durable encoding: all source pins occur once, while each full
   * live observation/probe is retained by digest and an explicit shared-files
   * reference. Live private handles and the Python wire ABI are unchanged.
   * This does not truncate history, omit a pin or raise the 64 KiB row bound. */
  private payload(ledger = this.ledger) {
    const files = this.profile.files;
    const filesSha256 = digest(files);
    const peers = ledger.peers.map(peer => {
      if (canonical(peer.observation.files) !== canonical(files)) fail('PEER_BINDING');
      const { files: _files, ...value } = peer.observation;
      const raw = value.observation.probe;
      let probe: unknown = null;
      if (raw !== null) {
        const sharesFiles = Object.hasOwn(raw, 'files') && canonical(raw.files) === canonical(files);
        const data = { ...raw };
        if (sharesFiles) delete data.files;
        probe = { sha256: digest(raw), filesRef: sharesFiles ? filesSha256 : null, data };
      }
      return { ...peer, observationSha256: digest(peer.observation), observation: {
        ...value, filesRef: filesSha256, observation: { ...value.observation, probe } } };
    });
    return canonical({ ...ledger, pinnedFiles: files, pinnedFilesSha256: filesSha256, peers });
  }
  private receipt(peer: PeerRecord, value = peer.observation) {
    const handle = Object.freeze(Object.create(null)) as object;
    receipts.set(handle, { owner: this, peerId: peer.peerId, revision: peer.revision, value: structuredClone(value) });
    return handle;
  }
  private async exclusive<T>(body: () => Promise<T>) {
    this.assertCurrent();
    if (this.busy) fail('BUSY');
    this.busy = true;
    try { return await body(); }
    catch (error) { await this.terminate('UNKNOWN'); throw error; }
    finally { this.busy = false; }
  }
  async acceptOriginal() {
    return this.exclusive(async () => {
      const { descriptor, observed } = this.peerResult(await this.request('accept', {}));
      if (observed.observation.state !== 'CONNECTED' || this.ledger.peers.some(x =>
          x.instanceId === observed.instanceId || x.peerId === observed.peerId || x.identity === digest(observed.process)))
        fail('PEER_ALREADY_CLAIMED');
      const peer: PeerRecord = { instanceId: observed.instanceId, peerId: observed.peerId,
        identity: digest(observed.process), phase: 'CONNECTED', originalBootstrapSha256: descriptor.originalBootstrapSha256,
        definitionDigest: descriptor.definitionDigest, revision: 1, observation: observed };
      this.ledger.peers.push(peer);
      await this.save();
      // This durable transition precedes the original peer's loaded challenge.
      const loaded = this.peerResult(await this.request('loaded', { peerId: peer.peerId }), peer).observed;
      if (loaded.observation.state !== 'LOADED' || !hash(loaded.observation.loadedNonce) ||
          loaded.observation.activeOperations !== 0 || loaded.observation.unknownOperations !== 0) fail('LOADED_UNKNOWN');
      peer.phase = 'LOADED'; peer.revision++; peer.observation = loaded;
      await this.save();
      return this.receipt(peer);
    });
  }
  async current(handle: object) {
    return this.exclusive(async () => {
      const previous = readOriginalPublicationPeerReceipt(handle, this);
      const peer = this.ledger.peers.find(x => x.peerId === previous.peerId)!;
      const observed = this.peerResult(await this.request('current', { peerId: peer.peerId }), peer).observed;
      const stable = (v: OriginalPublicationPeerObservation) => ({ ...v,
        observation: { ...v.observation, probe: null } });
      if (canonical(stable(observed)) !== canonical(stable(previous))) fail('PEER_CHANGED');
      if (!this.row || canonical(await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key)) !== canonical(this.row))
        fail('LEDGER_CHANGED');
      return this.receipt(peer, observed);
    });
  }
  async probe(handle: object, challenge: Record<string, unknown>) {
    return this.exclusive(async () => {
      const previous = readOriginalPublicationPeerReceipt(handle, this);
      const peer = this.ledger.peers.find(x => x.peerId === previous.peerId)!;
      const observed = this.peerResult(await this.request('probe', { peerId: peer.peerId, challenge }), peer).observed;
      if (observed.observation.state !== peer.phase || observed.observation.loadedNonce !== previous.observation.loadedNonce ||
          observed.observation.activeOperations !== 0 || observed.observation.unknownOperations !== 0 ||
          !observed.observation.probe || typeof observed.observation.probe !== 'object') fail('PROBE_UNKNOWN');
      // A read-only challenge does not rewrite history, extend a lease or mint
      // a new lifecycle revision. Its actual reply remains a private handle.
      return this.receipt(peer, observed);
    });
  }
  /** CI preparation retains the original local control locks/state/log writes.
   * Runner, controller and remote lifecycle effects pause individually until
   * a durable Main permit arrives; preparation is not a read-only OS probe. */
  async prepareCI(handle: object) { return this.ciExchange(handle, 'ci-prepare'); }
  /** The original peer condition wait is bounded by the unchanged session TTL. */
  async pollCI(handle: object) { return this.ciExchange(handle, 'ci-poll'); }
  async admitCIEffect(handle: object, permit: object) { return this.ciExchange(handle, 'effect-admit', permit); }
  async acknowledgeCIEffect(handle: object, permit: object) { return this.ciExchange(handle, 'effect-ack', permit); }
  private async ciExchange(handle: object, method: 'ci-prepare' | 'ci-poll' | 'effect-admit' | 'effect-ack', permit?: object) {
    return this.exclusive(async () => {
      const previous = readOriginalPublicationPeerReceipt(handle, this);
      const peer = this.ledger.peers.find(x => x.peerId === previous.peerId)!;
      if (previous.sourceScope !== 'REGISTERED_CI_PRODUCER' || previous.observation.unknownOperations !== 0 ||
          (method === 'ci-prepare' ? previous.observation.state !== 'LOADED' :
            !['RUNNING', 'FINISHED'].includes(previous.observation.state))) fail('CI_PHASE');
      const before = previous.observation.ciEffect;
      if ((method === 'ci-prepare' && before !== null) ||
          (method === 'effect-admit' && before?.state !== 'REQUESTED') ||
          (method === 'effect-ack' && before?.state !== 'SUCCEEDED')) fail('CI_PHASE');
      const args: Record<string, unknown> = { peerId: peer.peerId };
      if (method === 'effect-admit' || method === 'effect-ack') {
        if (!permit) fail('CI_PRIVATE_PERMIT_REQUIRED');
        Object.assign(args, await consumeOriginalCIEffectPermit(permit, this, previous,
          method === 'effect-admit' ? 'admit' : 'ack'));
      }
      const observed = this.peerResult(await this.request(method, args), peer).observed;
      const after = observed.observation.ciEffect;
      if (observed.observation.loadedNonce !== previous.observation.loadedNonce ||
          observed.observation.fenceRevision !== previous.observation.fenceRevision ||
          observed.observation.unknownOperations !== 0 || observed.observation.state === 'UNKNOWN' ||
          after?.state === 'UNKNOWN') fail('CI_OUTCOME_UNKNOWN');
      if (method === 'ci-prepare') {
        if (observed.observation.state !== 'RUNNING' || after !== null) fail('CI_PHASE');
      } else if (method === 'effect-admit' || method === 'effect-ack') {
        if (!before || !after || observed.observation.state !== 'RUNNING' || after.sequence !== before.sequence ||
            after.effectId !== before.effectId || canonical(after.descriptor) !== canonical(before.descriptor) ||
            after.admissionId !== args.admissionId || after.state !== (method === 'effect-admit' ? 'ADMITTED' : 'ACKNOWLEDGED') ||
            (method === 'effect-ack' && after.outcomeSha256 !== args.outcomeSha256)) fail('CI_EFFECT_BINDING');
      } else if (before === null) {
        if (after !== null && (after?.state !== 'REQUESTED' || after.sequence !== 1)) fail('CI_EFFECT_SEQUENCE');
      } else if (before && after && before.state === 'ACKNOWLEDGED' && after.state === 'REQUESTED') {
        if (after.sequence !== before.sequence + 1 || after.effectId === before.effectId) fail('CI_EFFECT_SEQUENCE');
      } else {
        if (!before || !after || after.sequence !== before.sequence || after.effectId !== before.effectId ||
            canonical(after.descriptor) !== canonical(before.descriptor) || after.admissionId !== before.admissionId ||
            !({ REQUESTED: ['REQUESTED'], ADMITTED: ['ADMITTED', 'RUNNING', 'SUCCEEDED'],
              RUNNING: ['RUNNING', 'SUCCEEDED'], SUCCEEDED: ['SUCCEEDED'], ACKNOWLEDGED: ['ACKNOWLEDGED'],
              UNKNOWN: [] } as Record<string, string[]>)[before.state].includes(after.state) ||
            (before.outcomeSha256 !== null && after.outcomeSha256 !== before.outcomeSha256)) fail('CI_EFFECT_SEQUENCE');
      }
      if (observed.observation.state === 'FINISHED' &&
          (after !== null && after?.state !== 'ACKNOWLEDGED')) fail('CI_OUTCOME_UNKNOWN');
      peer.phase = observed.observation.state; peer.revision++; peer.observation = observed;
      await this.save();
      return this.receipt(peer);
    });
  }
  async transition(handle: object, method: 'fence' | 'drain' | 'retire') {
    return this.exclusive(async () => {
      const previous = readOriginalPublicationPeerReceipt(handle, this);
      const peer = this.ledger.peers.find(x => x.peerId === previous.peerId)!;
      const expectedPhase = { fence: 'LOADED', drain: 'FENCED', retire: 'DRAINED' }[method];
      const completedCI = method === 'fence' && previous.sourceScope === 'REGISTERED_CI_PRODUCER' &&
        peer.phase === 'FINISHED' && previous.observation.activeOperations === 0 &&
        previous.observation.unknownOperations === 0;
      if (peer.phase !== expectedPhase && !completedCI) fail('PHASE');
      peer.phase = { fence: 'FENCING', drain: 'DRAINING', retire: 'RETIRING' }[method] as PeerRecord['phase'];
      peer.revision++;
      await this.save();
      const observed = this.peerResult(await this.request(method, { peerId: peer.peerId }), peer).observed;
      const phase = { fence: 'FENCED', drain: 'DRAINED', retire: 'RETIRED' }[method] as Phase;
      if (observed.observation.state !== phase || observed.observation.fenceRevision < 1 ||
          observed.observation.activeOperations !== 0 || observed.observation.unknownOperations !== 0) fail('DRAIN_UNKNOWN');
      peer.phase = phase; peer.revision++; peer.observation = observed;
      await this.save(method !== 'fence');
      return this.receipt(peer);
    });
  }
  /** Retain only a terminal channel, before the original LOADED binding is
   * invalidated. This never retains an effect admission or extends the lease. */
  async retainForPolicyCutover(controller: ManagedPublicationController, lifecycleHandle: object) {
    return this.exclusive(async () => {
      if (!(controller instanceof ManagedPublicationController) || this.retainedCutover ||
          this.policyRevision === undefined || !hash(this.policySha256)) fail('CUTOVER_OWNER');
      const lifecycle = await controller.verifyLifecycleReceipt(lifecycleHandle);
      if (lifecycle.phase !== 'LOADED' || lifecycle.operationId !== this.operationId ||
          canonical(lifecycle.binding) !== canonical(this.expected)) fail('CUTOVER_BINDING');
      const expectedIds = this.profile.owners.map(x => x.instanceId).sort();
      if (canonical(this.ledger.peers.map(x => x.instanceId).sort()) !== canonical(expectedIds) ||
          this.ledger.peers.some(x => x.phase !== 'RETIRED' || x.observation.observation.state !== 'RETIRED' ||
            x.observation.observation.activeOperations !== 0 || x.observation.observation.unknownOperations !== 0 ||
            x.observation.observation.fenceRevision < 1)) fail('CUTOVER_UNRETIRED');
      for (const peer of this.ledger.peers) {
        const observed = this.peerResult(await this.request('current', { peerId: peer.peerId }), peer).observed;
        if (canonical(observed) !== canonical(peer.observation)) fail('CUTOVER_PEER_CHANGED');
      }
      this.ledger.state = 'CUTOVER_HELD';
      await this.save(true);
      const handle = Object.freeze(Object.create(null)) as object;
      cutovers.set(handle, { owner: this, controller, binding: structuredClone(this.expected),
        row: structuredClone(this.row!), peerIds: this.ledger.peers.map(x => x.peerId).sort(),
        policyRevision: this.policyRevision, policySha256: this.policySha256!, consumed: false });
      this.retainedCutover = handle;
      return handle;
    });
  }
  private async verifyCutover(handle: object, drainedHandle: object, allowTerminal = false) {
    const retained = cutovers.get(handle);
    if (!retained || retained.owner !== this || this.retainedCutover !== handle || this.closed ||
        performance.now() - this.started >= TTL || (this.childClosed && !allowTerminal)) fail('PRIVATE_CUTOVER_REQUIRED');
    const actual = await retained.controller.verifyLifecycleReceipt(drainedHandle);
    if (actual.phase !== 'DRAINED' || actual.operationId !== this.operationId ||
        actual.binding.accountId !== this.expected.accountId || actual.binding.deviceId !== this.expected.deviceId ||
        actual.binding.bootId !== this.expected.bootId || actual.binding.generation !== this.expected.generation ||
        actual.binding.ownerEpoch <= this.expected.ownerEpoch || actual.ownedJobs !== 0 ||
        actual.unresolvedAdmissions !== 0 || actual.unknownNativeEffects !== 0) fail('CUTOVER_DRAIN_BINDING');
    await this.verifyPinnedFiles();
    const row = await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key);
    if (canonical(row) !== canonical(retained.row) || canonical(this.row) !== canonical(retained.row))
      fail('CUTOVER_LEDGER_CHANGED');
    await retained.controller.verifyLifecycleReceipt(drainedHandle);
    return { retained, actual };
  }
  retainedPolicyProfile(handle: object): Readonly<PinnedPublicationResidentSource> {
    const retained = cutovers.get(handle);
    if (!retained || retained.owner !== this || retained.consumed || this.retainedCutover !== handle ||
        this.closed || performance.now() - this.started >= TTL) fail('PRIVATE_CUTOVER_REQUIRED');
    return structuredClone(this.profile);
  }
  /** Exactly one terminal rotate over the original held FD. The old binding is
   * used on that wire; authority comes from the actual newer DRAINED handle. */
  async rotatePreparedPolicy(handle: object, nextProfile: PinnedPublicationResidentSource,
    drainedHandle: object, registry: RestrictedPublicationOwnerRegistry, retirementReceipt: object) {
    const retained = cutovers.get(handle);
    if (!retained || retained.owner !== this || retained.consumed) fail('PRIVATE_CUTOVER_REQUIRED');
    retained.consumed = true;
    try {
      await this.verifyCutover(handle, drainedHandle);
      const retired = await verifyOriginalRetirementReceipt(retirementReceipt, registry, this,
        retained.controller, drainedHandle);
      const next = structuredClone(nextProfile);
      exact(next, 'root,files,python,sourceDigest,runtimeDirectory,owners');
      exact(next.python, 'path,sha256');
      if (next.runtimeDirectory !== this.profile.runtimeDirectory || !hash(next.sourceDigest) ||
          !path.isAbsolute(next.root) || await realpath(next.root) !== next.root ||
          !next.files || Object.keys(next.files).length < 1 || Object.keys(next.files).length > 256 ||
          !Array.isArray(next.owners) || next.owners.length < 1 || next.owners.length > 64) fail('NEXT_POLICY');
      let total = 0;
      for (const [relativePath, expectedHash] of Object.entries(next.files)) {
        if (!relative(relativePath)) fail('NEXT_POLICY');
        total += (await pinned(path.join(next.root, relativePath), expectedHash, 4 * TOTAL)).size;
        if (total > 64 * TOTAL) fail('SOURCE_BUDGET');
      }
      await pinned(next.python.path, next.python.sha256, 128 * TOTAL);
      const ids = new Set<string>();
      for (const descriptor of next.owners) {
        exact(descriptor, 'instanceId,ownerId,sourceScope,entryScript,originalEntryScript,originalRoot,originalArgv,entryArgv,originalBootstrapSha256,definitionDigest');
        if (!opaque(descriptor.instanceId) || ids.has(descriptor.instanceId) ||
            this.profile.owners.some(x => x.instanceId === descriptor.instanceId) ||
            !opaque(descriptor.ownerId) ||
            !['RESIDENT_ORIGINAL_ENTRY', 'REGISTERED_NAMESPACE_OWNER', 'REGISTERED_RESIDENT_NONPUBLISHER',
              'REGISTERED_CI_PRODUCER'].includes(descriptor.sourceScope) ||
            !relative(descriptor.entryScript) || !relative(descriptor.originalEntryScript) ||
            !path.isAbsolute(descriptor.originalRoot) || path.normalize(descriptor.originalRoot) !== descriptor.originalRoot ||
            !Array.isArray(descriptor.originalArgv) || !descriptor.originalArgv.length ||
            descriptor.originalArgv.length > 64 || !descriptor.originalArgv.every(opaque) ||
            !Array.isArray(descriptor.entryArgv) || descriptor.entryArgv.length < 4 ||
            descriptor.entryArgv.length > 64 || !descriptor.entryArgv.every(opaque) ||
            (descriptor.sourceScope !== 'REGISTERED_CI_PRODUCER' &&
              next.files[descriptor.originalEntryScript] !== descriptor.originalBootstrapSha256) ||
            !hash(next.files[descriptor.entryScript]) || !hash(descriptor.definitionDigest) ||
            canonical(descriptor.entryArgv.slice(0, 4)) !==
              canonical([next.python.path, '-I', '-B', path.join(next.root, descriptor.entryScript)])) fail('NEXT_POLICY');
        if (descriptor.sourceScope === 'REGISTERED_CI_PRODUCER')
          originalCIProducerBootstrap(descriptor as OriginalPublicationOwnerDescriptor, next.files);
        ids.add(descriptor.instanceId);
        const claimKey = digest(['publication-original-instance-claim/v1', this.expected.deviceId, descriptor.instanceId]);
        if (await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, claimKey))
          fail('INSTANCE_ALREADY_CLAIMED');
      }
      const nextPolicy = { schema: 'publication-owner-policy/v1', runtimeDirectory: next.runtimeDirectory,
        sourceRoot: next.root, sourceDigest: next.sourceDigest, sourceFiles: next.files,
        resolvedInterpreter: next.python.path, interpreterSha256: next.python.sha256, owners: next.owners };
      const nextPolicySha256 = createHash('sha256').update(canonical(nextPolicy) + '\n').digest('hex');
      await this.verifyCutover(handle, drainedHandle);
      const history = await this.store.capturePublicationOwnerHistory(this.plugin, this.expected.accountId);
      const original = readPublicationHistoryReceipt(history, this.store.consumerGuardReceiptIdentity,
        this.plugin, this.expected.accountId);
      // Capture first, then verify every private participant against that same
      // snapshot. A fresh snapshot cannot adopt a competing registry winner.
      await this.verifyCutover(handle, drainedHandle);
      await verifyOriginalRetirementReceipt(retirementReceipt, registry, this, retained.controller, drainedHandle);
      for (const descriptor of next.owners) {
        const claimKey = digest(['publication-original-instance-claim/v1', this.expected.deviceId, descriptor.instanceId]);
        if (await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, claimKey))
          fail('INSTANCE_ALREADY_CLAIMED');
      }
      const pending = { ...this.ledger, state: 'ROTATING_UNKNOWN' as const };
      if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key,
        retained.row, this.payload(pending), true, history)) fail('CUTOVER_LEDGER_CHANGED');
      this.ledger = pending;
      this.row = retained.row = { revision: retained.row.revision + 1, payload: this.payload(pending) };
      await this.verifyCutover(handle, drainedHandle);
      this.terminalExpected = true;
      const result = await this.exchange({ schema: SCHEMA, sessionId: this.sessionId, operationId: this.operationId,
        binding: this.expected, seq: this.sequence + 1, nonce: this.nextNonce, method: 'rotate', args: {
          expectedPolicySha256: retained.policySha256, expectedRevision: retained.policyRevision, nextPolicy,
          drainProof: { schema: 'publication-main-policy-drain/v1', sessionId: this.sessionId,
            operationId: this.operationId, binding: this.expected, receiptId: retired.receiptId,
            snapshotSha256: original.sha256, retiredPeerIds: retained.peerIds,
            unresolvedAdmissions: 0, unknownNativeEffects: 0, unobservedInstances: 0 },
        } }, this.sequence + 1, true);
      exact(result, 'state,previousPolicySha256,nextPolicySha256,revision');
      if (result.state !== 'POLICY_PREPARED' || result.previousPolicySha256 !== retained.policySha256 ||
          result.nextPolicySha256 !== nextPolicySha256 || result.revision !== retained.policyRevision + 1 ||
          !this.terminalFrameReceived) fail('CUTOVER_RESULT');
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([this.childExit!, new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(Error('PUBLICATION_RESIDENT_SOURCE_CUTOVER_EXIT_UNKNOWN')),
            Math.max(1, Math.min(1000, TTL - (performance.now() - this.started))));
        })]);
      } finally { if (timer) clearTimeout(timer); }
      if (!this.childClosed || this.childExitCode !== 0 || !this.responseEOF || this.buffer.length !== 0) fail('CUTOVER_EXIT_UNKNOWN');
      await this.verifyCutover(handle, drainedHandle, true);
      await verifyOriginalRetirementReceipt(retirementReceipt, registry, this, retained.controller, drainedHandle);
      const finalHistory = await this.store.capturePublicationOwnerHistory(this.plugin, this.expected.accountId);
      await this.verifyCutover(handle, drainedHandle, true);
      await verifyOriginalRetirementReceipt(retirementReceipt, registry, this, retained.controller, drainedHandle);
      const finished: Ledger = { ...this.ledger, state: 'POLICY_PREPARED', preparedPolicy: {
        previousPolicySha256: retained.policySha256, nextPolicySha256, revision: result.revision } };
      if (!await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key,
        retained.row, this.payload(finished), true, finalHistory)) fail('CUTOVER_LEDGER_CHANGED');
      this.ledger = finished;
      this.row = retained.row = { revision: retained.row.revision + 1, payload: this.payload(finished) };
      this.closed = true;
      if (this.deadline) clearTimeout(this.deadline);
      return Object.freeze({ ...finished.preparedPolicy });
    } catch (error) { await this.terminate('UNKNOWN'); throw error; }
  }
  /** After terminal EOF, the only remaining proof is the exact durable winner
   * plus the original DRAINED/registry handles. Old bootstrap bytes may now be
   * replaced, so this never resurrects the old live source or a peer receipt. */
  async verifyPreparedPolicy(handle: object, drainedHandle: object,
    registry: RestrictedPublicationOwnerRegistry, retirementReceipt: object) {
    const result = await this.verifyPreparedPolicyRecord(handle);
    const retained = cutovers.get(handle)!;
    await verifyOriginalRetirementReceipt(retirementReceipt, registry, this, retained.controller, drainedHandle);
    return result;
  }
  /** A retained terminal journal fact remains checkable after the new original
   * Controller epoch. It does not validate any new owner or provide a lease. */
  async verifyPreparedPolicyRecord(handle: object) {
    const retained = cutovers.get(handle);
    if (!retained || retained.owner !== this || !retained.consumed || this.retainedCutover !== handle ||
        !this.closed || !this.childClosed || this.childExitCode !== 0 || !this.responseEOF || !this.terminalFrameReceived ||
        this.ledger.state !== 'POLICY_PREPARED' || !this.ledger.preparedPolicy ||
        canonical(this.row) !== canonical(retained.row) ||
        canonical(await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key)) !==
          canonical(retained.row)) fail('PRIVATE_POLICY_PREPARATION_REQUIRED');
    return Object.freeze({ ...this.ledger.preparedPolicy });
  }
  diagnostics() {
    return { state: this.ledger.state, observedPeers: this.ledger.peers.length,
      scope: 'ORIGINAL_PEERS_ONLY' as const, releaseCalls: 0, closed: this.closed,
      policyRevision: this.policyRevision ?? null, policySha256: this.policySha256 ?? null };
  }
  /** Immutable launch expectations only; never a source or census receipt. */
  originalDescriptor(instanceId: string) {
    this.assertCurrent();
    const descriptor = this.profile.owners.find(x => x.instanceId === instanceId);
    if (!descriptor) fail('PROFILE');
    return structuredClone(descriptor);
  }
  binding() { this.assertCurrent(); return structuredClone(this.expected); }
  async revoke() { if (this.ledger.state !== 'POLICY_PREPARED') await this.terminate('REVOKED'); }
  private async terminate(state: 'UNKNOWN' | 'REVOKED') {
    if (this.closing) return this.closing;
    this.closed = true;
    if (this.deadline) clearTimeout(this.deadline);
    const pending = this.pending; this.pending = undefined;
    if (pending) { clearTimeout(pending.timer); pending.reject(Error('PUBLICATION_RESIDENT_SOURCE_CLOSED')); }
    this.closing = (async () => {
      // Kill only our listener. A foreign or recycled peer PID is never signalled.
      this.child?.kill('SIGTERM');
      if (this.childExit) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const exited = await Promise.race([this.childExit.then(() => true), new Promise<boolean>(resolve => {
          timer = setTimeout(() => resolve(false), 1000);
        })]);
        if (timer) clearTimeout(timer);
        if (!exited && this.child && !this.childClosed) { this.child.kill('SIGKILL'); await this.childExit; }
      }
      if (this.row) {
        const next = { ...this.ledger, state: ['UNKNOWN', 'ROTATING_UNKNOWN', 'CUTOVER_HELD'].includes(this.ledger.state)
          ? 'UNKNOWN' as const : state };
        try {
          if (await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.expected.accountId,
              this.key, this.row, this.payload(next))) this.ledger = next;
        } catch { /* Original UNKNOWN and a concurrent winner are retained. */ }
      }
    })();
    return this.closing;
  }
}
