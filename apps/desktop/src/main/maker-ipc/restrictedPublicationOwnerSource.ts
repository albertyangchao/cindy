/** Main-private holder of one original publisher source process. This is not a
 * resident census, a restored authority, or a claim about another OS process. */
import { spawn, type ChildProcess } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { Readable, Writable } from 'node:stream';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import type { PublicationSourceBinding } from './restrictedPublicationCISourceBroker.js';
import { canonical, digest, parseNativeFrame } from './restrictedPublicationProtocol.js';

const SCHEMA = 'publication-owner-source/v1';
const ENTRY = 'scripts/publish_html_report.py';
const FRAME = 65536;
const TOTAL = 1048576;
const TTL = 60000;
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 &&
  Buffer.byteLength(v) <= 512 && !/[\u0000-\u001f\u007f]/.test(v);
function fail(code: string): never { throw Error('PUBLICATION_OWNER_SOURCE_' + code); }
function keys(v: unknown, names: string): asserts v is Record<string, any> {
  if (!v || typeof v !== 'object' || Array.isArray(v) ||
      Object.keys(v).sort().join(',') !== names.split(',').sort().join(',')) fail('SCHEMA');
}
function checkBinding(v: PublicationSourceBinding) {
  keys(v, 'accountId,deviceId,bootId,ownerEpoch,generation');
  if (!hex(v.accountId) || !hex(v.deviceId) || !text(v.bootId) || !text(v.generation) ||
      !Number.isSafeInteger(v.ownerEpoch) || v.ownerEpoch < 0) fail('BINDING');
  return structuredClone(v);
}
type Store = Pick<ReturnType<typeof createRestrictedPartnerStore>,
  'consumerGuardReceiptIdentity' | 'readConsumerGuardReceipt' | 'compareAndSwapConsumerGuardReceipt' |
  'unresolvedConsumerGuardAdmissions' | 'unknownNativePublicationEffects'>;
type Row = Awaited<ReturnType<Store['readConsumerGuardReceipt']>>;
export interface PinnedPublicationOwnerSource {
  root: string;
  files: Readonly<Record<string, string>>;
  python: { path: string; sha256: string };
  sourceDigest: string;
  instanceId: string;
  /** A selection label only. It never proves the identity of an OS service. */
  profileId: 'canonical-producer' | 'core.monitor.publish';
  definitionDigest: string;
}
type Phase = 'LOADED' | 'FENCED' | 'DRAINED';
type State = 'STARTING' | Phase | 'FENCING' | 'DRAINING' | 'RETIRING' | 'RETIRED' | 'REVOKED' | 'UNKNOWN';
type Ledger = {
  schema: 'publication-held-owner-source/v1';
  scope: 'HELD_SOURCE_PROCESS';
  operationId: string;
  binding: PublicationSourceBinding;
  instanceId: string;
  profileSha256: string;
  state: State;
  processId: number | null;
  events: Array<{ state: State; processId: number | null }>;
};
export interface HeldPublicationOwnerObservation {
  schema: 'publication-main-held-source/v1';
  scope: 'HELD_SOURCE_PROCESS';
  operationId: string;
  binding: PublicationSourceBinding;
  phase: Phase;
  ledgerRevision: number;
  processId: number;
  instanceId: string;
  entryId: 'canonical-producer';
  profileId: 'canonical-producer' | 'core.monitor.publish';
  definitionDigest: string;
  root: string;
  sourceDigest: string;
  files: Readonly<Record<string, string>>;
  resolvedInterpreter: string;
  entryScript: typeof ENTRY;
  loadedNonce: string;
  nativeWithoutMain: 'DENIED';
  businessEffects: 0;
  /** Counts for the source-only process, never the global business inventory. */
  activeAdmissions: 0;
  unknownNativeEffects: 0;
  fenceRevision: 0 | 1;
}
type Pin = { file: string; sha256: string; maximum: number; identity: string };
const identity = (s: Awaited<ReturnType<typeof lstat>>) =>
  [s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs].join(':');
async function pinFile(file: string, expected: string, maximum: number) {
  if (!hex(expected) || !path.isAbsolute(file) || path.normalize(file) !== file ||
      await realpath(file) !== file) fail('PIN');
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o022) ||
      before.size > maximum) fail('PIN');
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (identity(await fd.stat()) !== identity(before)) fail('SOURCE_CHANGED');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(65536);
    let total = 0;
    while (true) {
      const { bytesRead } = await fd.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      total += bytesRead;
      if (total > before.size) fail('SOURCE_CHANGED');
      hash.update(buffer.subarray(0, bytesRead));
    }
    if (total !== before.size || hash.digest('hex') !== expected ||
        identity(await fd.stat()) !== identity(before) || identity(await lstat(file)) !== identity(before) ||
        await realpath(file) !== file) fail('SOURCE_CHANGED');
    return { identity: identity(before), size: total };
  } finally { await fd.close(); }
}
async function settled(done: Promise<void>, milliseconds: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([done.then(() => true), new Promise<boolean>(resolve => {
      timer = setTimeout(() => resolve(false), milliseconds);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}
const owners = new WeakSet<object>();
const receipts = new WeakMap<object, {
  owner: RestrictedPublicationOwnerSource; revision: number; value: HeldPublicationOwnerObservation;
}>();
export function readHeldPublicationOwnerReceipt(handle: object, owner: RestrictedPublicationOwnerSource) {
  const r = receipts.get(handle);
  if (!r || r.owner !== owner || !owners.has(owner)) fail('PRIVATE_RECEIPT_REQUIRED');
  owner.assertReceiptRevision(r.revision);
  return structuredClone(r.value);
}

export class RestrictedPublicationOwnerSource {
  private readonly profile: PinnedPublicationOwnerSource;
  private readonly expected: PublicationSourceBinding;
  private readonly started = performance.now();
  private readonly sessionId = randomBytes(32).toString('hex');
  private readonly initNonce = randomBytes(32).toString('hex');
  private readonly key: string;
  private row: Row;
  private ledger: Ledger;
  private pins: Pin[] = [];
  private directories = new Map<string, string>();
  private child?: ChildProcess;
  private exited?: Promise<void>;
  private childClosed = false;
  private exitCode: number | null = null;
  private exitSignal: string | null = null;
  private terminalReply = false;
  private closed = false;
  private busy = false;
  private closing?: Promise<void>;
  private deadline?: ReturnType<typeof setTimeout>;
  private lastWall = Date.now();
  private sequence = 0;
  private nextNonce: string | null = null;
  private loadedNonce?: string;
  private wireState = 'OPEN';
  private revision = 0;
  private observed?: Record<string, any>;
  private input = Buffer.alloc(0);
  private inputBytes = 0;
  private outputBytes = 0;
  private pending?: {
    sequence: number; method: string; nonce: string; timer: ReturnType<typeof setTimeout>;
    resolve: (value: Record<string, any>) => void; reject: (error: Error) => void;
  };
  private constructor(private readonly store: Store, private readonly plugin: string,
    readonly operationId: string, profile: PinnedPublicationOwnerSource, expected: PublicationSourceBinding,
    private readonly currentBinding: () => PublicationSourceBinding) {
    this.expected = checkBinding(expected);
    keys(profile, 'root,files,python,sourceDigest,instanceId,profileId,definitionDigest');
    keys(profile.python, 'path,sha256');
    if (!text(plugin) || !text(operationId) || !text(profile.instanceId) || !hex(profile.sourceDigest) ||
        !hex(profile.definitionDigest) || !['canonical-producer', 'core.monitor.publish'].includes(profile.profileId))
      fail('PROFILE');
    this.profile = structuredClone(profile);
    // Stable across boots/generations: a crashed or retired instance ID is never restarted.
    this.key = digest(['publication-held-owner-source/v1', expected.deviceId, profile.instanceId]);
    this.ledger = { schema: 'publication-held-owner-source/v1', scope: 'HELD_SOURCE_PROCESS',
      operationId, binding: this.expected, instanceId: profile.instanceId, profileSha256: digest(this.profile),
      state: 'STARTING', processId: null, events: [{ state: 'STARTING', processId: null }] };
    owners.add(this);
  }
  static async startOwned(store: Store, plugin: string, operationId: string,
    profile: PinnedPublicationOwnerSource, expected: PublicationSourceBinding,
    currentBinding: () => PublicationSourceBinding) {
    const self = new RestrictedPublicationOwnerSource(store, plugin, operationId, profile, expected, currentBinding);
    self.assertCurrent();
    if (await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key) ||
        !await store.compareAndSwapConsumerGuardReceipt(plugin, expected.accountId, self.key, undefined,
          JSON.stringify(self.ledger))) fail('INSTANCE_ALREADY_CLAIMED');
    try {
      self.row = await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key);
      if (!self.row || self.row.revision !== 1 || self.row.payload !== JSON.stringify(self.ledger)) fail('LEDGER_CHANGED');
      await self.capturePins();
      self.launch();
      if (!Number.isSafeInteger(self.child?.pid) || self.child!.pid! < 1) fail('SPAWN');
      await self.save('STARTING', self.child!.pid!);
      await self.request('init');
      await self.request('loaded');
      await self.save('LOADED');
      return self;
    } catch (error) { await self.terminate('UNKNOWN'); throw error; }
  }
  private async capturePins() {
    const p = this.profile;
    if (!path.isAbsolute(p.root) || path.normalize(p.root) !== p.root || await realpath(p.root) !== p.root ||
        !(await lstat(p.root)).isDirectory() || !p.files || typeof p.files !== 'object' || Array.isArray(p.files) ||
        Object.keys(p.files).length > 256 ||
        ![ENTRY, 'bridge_core/__init__.py', 'bridge_core/publication_owner_source.py',
          'bridge_core/publication_consumer_enrollment.py'].every(f => hex(p.files[f]))) fail('PROFILE');
    let total = 0;
    const add = async (file: string, expected: string, maximum: number) => {
      const pin = await pinFile(file, expected, maximum);
      this.pins.push({ file, sha256: expected, maximum, identity: pin.identity });
      for (let dir = path.dirname(file); ; dir = path.dirname(dir)) {
        const s = await lstat(dir);
        if (!s.isDirectory() || s.isSymbolicLink()) fail('PIN');
        const id = [s.dev, s.ino, s.mode].join(':');
        if (this.directories.has(dir) && this.directories.get(dir) !== id) fail('SOURCE_CHANGED');
        this.directories.set(dir, id);
        if (path.dirname(dir) === dir) break;
      }
      return pin.size;
    };
    for (const [relative, sha] of Object.entries(p.files)) {
      if (!relative || path.isAbsolute(relative) || relative.includes('\\') ||
          relative.split('/').some(x => !x || x === '.' || x === '..')) fail('PROFILE');
      total += await add(path.join(p.root, relative), sha, 8 * TOTAL);
      if (total > 64 * TOTAL) fail('SOURCE_BUDGET');
    }
    await add(p.python.path, p.python.sha256, 128 * TOTAL);
    this.assertCurrent();
  }
  private async verifyPins(allowExit = false) {
    this.assertCurrent(allowExit);
    for (const [dir, expected] of this.directories) {
      const s = await lstat(dir);
      if (!s.isDirectory() || s.isSymbolicLink() || [s.dev, s.ino, s.mode].join(':') !== expected)
        fail('SOURCE_CHANGED');
    }
    for (const p of this.pins)
      if ((await pinFile(p.file, p.sha256, p.maximum)).identity !== p.identity) fail('SOURCE_CHANGED');
    this.assertCurrent(allowExit);
  }
  private assertCurrent(allowExit = false) {
    const now = Date.now();
    if (this.closed || performance.now() - this.started >= TTL || now < this.lastWall ||
        (this.childClosed && !(allowExit && this.terminalReply))) fail('CLOSED');
    this.lastWall = now;
    if (canonical(checkBinding(this.currentBinding())) !== canonical(this.expected)) fail('OWNER_CHANGED');
  }
  private inputChannel(): Writable {
    const channels: ReadonlyArray<Readable | Writable | null | undefined> | undefined = this.child?.stdio;
    const channel = channels?.[11];
    if (!channel || !('write' in channel) || typeof channel.write !== 'function') fail('CHANNEL_CLOSED');
    return channel as Writable;
  }
  assertReceiptRevision(revision: number) {
    try {
      this.assertCurrent();
      if (revision !== this.revision || !['LOADED', 'FENCED', 'DRAINED'].includes(this.ledger.state))
        fail('STALE_RECEIPT');
    } catch (error) { this.failClosed(); throw error; }
  }
  matchesOwner(store: object, plugin: string, expected: PublicationSourceBinding) {
    this.assertCurrent();
    return this.store.consumerGuardReceiptIdentity === store && this.plugin === plugin &&
      canonical(expected) === canonical(this.expected);
  }
  private launch() {
    this.assertCurrent();
    const p = this.profile;
    const child = spawn(p.python.path, ['-I', '-B', path.join(p.root, ENTRY), '--publication-owner-source'], {
      cwd: p.root, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['ignore', 'pipe', 'pipe', 'ignore', 'ignore', 'ignore', 'ignore', 'ignore', 'ignore',
        'ignore', 'ignore', 'pipe', 'pipe'],
    });
    this.child = child;
    this.exited = new Promise<void>(resolve => {
      child.once('error', () => this.failClosed());
      child.once('close', (code, signal) => {
        this.childClosed = true; this.exitCode = code; this.exitSignal = signal;
        if (!this.terminalReply) this.failClosed();
        resolve();
      });
    });
    for (const fd of [1, 2, 12]) {
      const stream = child.stdio[fd] as Readable;
      stream.on('data', (data: Buffer) => fd === 12 ? this.receive(data) : this.failClosed());
      stream.on('error', () => this.failClosed());
    }
    this.inputChannel().on('error', () => this.failClosed());
    const channels: ReadonlyArray<Readable | Writable | null | undefined> = child.stdio;
    const response = channels[12];
    if (!response || !('read' in response) || typeof response.read !== 'function') fail('CHANNEL_CLOSED');
    response.on('end', () => { if (!this.terminalReply) this.failClosed(); });
    this.deadline = setTimeout(() => this.failClosed(), Math.max(1, TTL - (performance.now() - this.started)));
  }
  private receive(data: Buffer) {
    if (this.closed) return;
    try {
      this.assertCurrent();
      this.inputBytes += data.length;
      if (this.inputBytes > TOTAL || this.input.length + data.length > FRAME) fail('FRAME_LIMIT');
      this.input = Buffer.concat([this.input, data]);
      const end = this.input.indexOf(10);
      if (end < 0) return;
      if (!end || end !== this.input.length - 1) fail('UNSOLICITED_FRAME');
      if (this.input.includes(0) || this.input.includes(13)) fail('FRAME_ENCODING');
      const frame = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(this.input.subarray(0, end)));
      this.input = Buffer.alloc(0);
      keys(frame, 'schema,sessionId,operationId,binding,seq,nextNonce,ok,code,result');
      const pending = this.pending;
      if (!pending || frame.schema !== SCHEMA || frame.sessionId !== this.sessionId ||
          frame.operationId !== this.operationId || canonical(frame.binding) !== canonical(this.expected) ||
          frame.seq !== pending.sequence || frame.ok !== true || frame.code !== null ||
          (pending.method === 'retire' ? frame.nextNonce !== null : !hex(frame.nextNonce))) fail('RESPONSE_BINDING');
      const r = frame.result;
      keys(r, 'scope,state,processId,instanceId,entryId,profileId,definitionDigest,root,sourceDigest,files,' +
        'resolvedInterpreter,entryScript,loadedNonce,nativeWithoutMain,businessEffects,activeAdmissions,unknownNativeEffects,fenceRevision');
      const p = this.profile;
      const state = ({ init: 'OPEN', loaded: 'LOADED', current: this.wireState, fence: 'FENCED',
        drain: 'DRAINED', retire: 'RETIRED' } as Record<string, string>)[pending.method];
      const nonce = pending.method === 'init' ? null : pending.method === 'loaded' ? pending.nonce : this.loadedNonce;
      if (r.scope !== 'HELD_SOURCE_PROCESS' || r.state !== state || r.processId !== this.child!.pid ||
          r.instanceId !== p.instanceId || r.entryId !== 'canonical-producer' || r.profileId !== p.profileId ||
          r.definitionDigest !== p.definitionDigest || r.root !== p.root || r.sourceDigest !== p.sourceDigest ||
          canonical(r.files) !== canonical(p.files) || r.resolvedInterpreter !== p.python.path || r.entryScript !== ENTRY ||
          r.loadedNonce !== nonce || r.nativeWithoutMain !== (pending.method === 'init' ? null : 'DENIED') ||
          r.businessEffects !== 0 || r.activeAdmissions !== 0 || r.unknownNativeEffects !== 0 ||
          r.fenceRevision !== (['FENCED', 'DRAINED', 'RETIRED'].includes(state) ? 1 : 0)) fail('SOURCE_FACTS');
      this.wireState = state;
      this.nextNonce = frame.nextNonce;
      if (pending.method === 'loaded') this.loadedNonce = pending.nonce;
      if (pending.method === 'retire') this.terminalReply = true;
      this.observed = structuredClone(r);
      clearTimeout(pending.timer); this.pending = undefined;
      pending.resolve(r);
    } catch { this.failClosed(); }
  }
  private async request(method: 'init' | 'loaded' | 'current' | 'fence' | 'drain' | 'retire') {
    if (this.pending || this.sequence >= 128) fail('REQUEST_STATE');
    await this.verifyPins();
    await this.verifyLedger();
    const nonce = method === 'init' ? this.initNonce : this.nextNonce;
    if (!hex(nonce)) fail('NONCE');
    const sequence = method === 'init' ? 0 : ++this.sequence;
    const p = this.profile;
    const frame = method === 'init' ? {
      schema: SCHEMA, sessionId: this.sessionId, operationId: this.operationId, binding: this.expected,
      instanceId: p.instanceId, entryId: 'canonical-producer', profileId: p.profileId, root: p.root,
      sourceDigest: p.sourceDigest, sourceFiles: p.files, resolvedInterpreter: p.python.path,
      definitionDigest: p.definitionDigest, expiresAt: Date.now() + Math.floor(TTL - (performance.now() - this.started)), nonce,
    } : { schema: SCHEMA, sessionId: this.sessionId, operationId: this.operationId, binding: this.expected,
      seq: sequence, nonce, method, args: {} };
    const raw = Buffer.from(canonical(frame) + '\n');
    if (raw.length > FRAME || (this.outputBytes += raw.length) > TOTAL) fail('FRAME_LIMIT');
    await new Promise<Record<string, any>>((resolve, reject) => {
      const timer = setTimeout(() => this.failClosed(), Math.min(10000, Math.max(1, TTL - (performance.now() - this.started))));
      this.pending = { sequence, method, nonce, timer, resolve, reject };
      this.inputChannel().write(raw, error => { if (error) this.failClosed(); });
    });
    await this.verifyPins(method === 'retire');
    await this.verifyLedger(method === 'retire');
  }
  private async verifyLedger(allowExit = false) {
    this.assertCurrent(allowExit);
    const row = await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key);
    this.assertCurrent(allowExit);
    if (!row || !this.row || row.revision !== this.row.revision || row.payload !== this.row.payload ||
        row.payload !== JSON.stringify(this.ledger)) fail('LEDGER_CHANGED');
  }
  private async save(state: State, pid = this.ledger.processId, terminalWrite = false) {
    if (!terminalWrite) await this.verifyLedger(this.terminalReply);
    const next: Ledger = { ...this.ledger, state, processId: pid,
      events: [...this.ledger.events, { state, processId: pid }] };
    if (!this.row || !await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.expected.accountId,
      this.key, this.row, JSON.stringify(next), state === 'DRAINED' || state === 'RETIRED')) fail('LEDGER_CHANGED');
    this.row = { revision: this.row.revision + 1, payload: JSON.stringify(next) };
    this.ledger = next;
    this.revision++;
    if (!terminalWrite) await this.verifyLedger(this.terminalReply);
  }
  private receipt() {
    this.assertCurrent();
    if (!this.row || !this.observed || !['LOADED', 'FENCED', 'DRAINED'].includes(this.ledger.state)) fail('STATE');
    const { state: _state, ...source } = this.observed;
    const value = { ...source, schema: 'publication-main-held-source/v1', operationId: this.operationId,
      binding: this.expected, phase: this.ledger.state, ledgerRevision: this.row.revision } as HeldPublicationOwnerObservation;
    const handle = Object.freeze(Object.create(null));
    receipts.set(handle, { owner: this, revision: this.revision, value: structuredClone(value) });
    return handle;
  }
  loadedReceipt() {
    if (this.ledger.state !== 'LOADED') fail('STATE');
    return this.receipt();
  }
  private async exclusive<T>(run: () => Promise<T>): Promise<T> {
    if (this.busy) fail('OVERLAPPING_REQUEST');
    this.busy = true;
    try { this.assertCurrent(); return await run(); }
    catch (error) { await this.terminate('UNKNOWN'); throw error; }
    finally { this.busy = false; }
  }
  async current(handle: object) {
    return this.exclusive(async () => {
      const before = readHeldPublicationOwnerReceipt(handle, this);
      await this.request('current');
      const after = readHeldPublicationOwnerReceipt(handle, this);
      if (canonical(before) !== canonical(after)) fail('CURRENT_CHANGED');
      return after;
    });
  }
  async fence(handle: object) {
    return this.exclusive(async () => {
      if (readHeldPublicationOwnerReceipt(handle, this).phase !== 'LOADED') fail('STATE');
      await this.save('FENCING'); // durable launch/admission closure precedes the child acknowledgement
      await this.request('fence');
      await this.save('FENCED');
      return this.receipt();
    });
  }
  private async assertDrained(allowExit = false) {
    this.assertCurrent(allowExit);
    if (await this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.expected.accountId) !== 0 ||
        await this.store.unknownNativePublicationEffects(this.plugin) !== 0) fail('DRAIN_UNKNOWN');
    this.assertCurrent(allowExit);
  }
  async drain(handle: object) {
    return this.exclusive(async () => {
      if (readHeldPublicationOwnerReceipt(handle, this).phase !== 'FENCED') fail('STATE');
      await this.assertDrained();
      await this.save('DRAINING');
      await this.request('drain');
      await this.assertDrained();
      await this.save('DRAINED');
      return this.receipt();
    });
  }
  async retire(handle: object) {
    return this.exclusive(async () => {
      if (readHeldPublicationOwnerReceipt(handle, this).phase !== 'DRAINED') fail('STATE');
      await this.assertDrained();
      await this.save('RETIRING');
      await this.request('retire');
      if (!await settled(this.exited!, 1500) || this.exitCode !== 0 || this.exitSignal !== null) fail('RETIRE_UNKNOWN');
      await this.assertDrained(true);
      await this.save('RETIRED');
      this.invalidate();
    });
  }
  diagnostics() {
    return Object.freeze({ scope: 'HELD_SOURCE_PROCESS', state: this.ledger.state,
      processId: this.ledger.processId, closed: this.closed, childReaped: this.childClosed });
  }
  private invalidate() {
    this.closed = true;
    this.revision++;
    if (this.deadline) clearTimeout(this.deadline);
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(Error('PUBLICATION_OWNER_SOURCE_CLOSED'));
      this.pending = undefined;
    }
  }
  private failClosed() { void this.terminate('UNKNOWN').catch(() => {}); }
  revoke(): Promise<void> { return this.terminate('REVOKED'); }
  private terminate(state: 'REVOKED' | 'UNKNOWN'): Promise<void> {
    this.invalidate();
    if (this.closing) return this.closing;
    if (this.ledger.state === 'RETIRED') return Promise.resolve();
    this.closing = (async () => {
      let reaped = true;
      if (this.child) {
        try { this.inputChannel().end(); } catch { /* proceed to owned process cleanup */ }
        if (!await settled(this.exited!, 1000)) {
          this.child.kill('SIGTERM');
          if (!await settled(this.exited!, 500)) {
            this.child.kill('SIGKILL');
            reaped = await settled(this.exited!, 1000);
          }
        }
      }
      // A foreign CAS winner remains untouched; termination never clears historical rows.
      try { await this.save(reaped ? state : 'UNKNOWN', this.ledger.processId, true); }
      catch { /* keep the original consumed record, including an unresolved transition */ }
      if (!reaped) fail('CLEANUP_UNKNOWN');
    })();
    return this.closing;
  }
}
