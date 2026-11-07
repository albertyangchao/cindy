/** Main-private owner of the fixed B worker and its original operation.
 * No IPC, plugin JSON importer, arbitrary child/argv, or production registration.
 * Python private pending/issued objects stay in the same owned process. A source
 * receipt proves only its declared scope; one CI run never proves all writers.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { Readable, Writable } from 'node:stream';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import { canonical, digest, parseNativeFrame } from './restrictedPublicationProtocol.js';
import {
  ManagedPublicationController,
  readManagedLifecycleReceipt,
} from './restrictedPublicationManagedController.js';

const SCHEMA = 'publication-coverage-source/v1';
const DEFINITION_SCHEMA = 'publication-definition-channel/v1';
const REPOSITORY = 'albertyangchao/core-bridge';
const WORKFLOW = '.github/workflows/publish-worksheet-html.yml';
const WORKER = 'scripts/publication_coverage_source_worker.py';
const FRAME = 65536;
const TOTAL = 1048576;
const hash = (x: string | Uint8Array) => createHash('sha256').update(x).digest('hex');
const hex = (x: unknown): x is string => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const positive = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) > 0;
const object = (x: unknown): x is Record<string, any> => !!x && typeof x === 'object' && !Array.isArray(x);
function fail(code: string): never { throw Error('PUBLICATION_SOURCE_' + code); }
function keys(x: unknown, expected: string) {
  if (!object(x) || Object.keys(x).sort().join(',') !== expected.split(',').sort().join(',')) fail('SCHEMA');
}
async function waitForExit(done: Promise<void>, milliseconds: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([done.then(() => true), new Promise<boolean>(resolve => {
      timer = setTimeout(() => resolve(false), milliseconds);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}
export interface PublicationSourceBinding {
  accountId: string;
  deviceId: string;
  bootId: string;
  ownerEpoch: number;
  generation: string;
}
function binding(value: PublicationSourceBinding) {
  keys(value, 'accountId,deviceId,bootId,ownerEpoch,generation');
  if (!Number.isSafeInteger(value.ownerEpoch) || value.ownerEpoch < 0 ||
      ['accountId', 'deviceId', 'bootId', 'generation'].some(k =>
        typeof value[k as keyof PublicationSourceBinding] !== 'string' ||
        !/^[A-Za-z0-9_.:@/-]{1,160}$/.test(String(value[k as keyof PublicationSourceBinding])))) fail('BINDING');
  return structuredClone(value);
}
export interface PinnedPublicationSourceWorker {
  root: string;
  files: Readonly<Record<string, string>>;
  python: { path: string; sha256: string };
  /** Original Main-approved CLI account context, never credential values. */
  gh: { path: string; sha256: string; homeDirectory: string; configDirectory: string };
  definition?: {
    monitorRoot: string;
    monitorSha256: string;
    profilePath: string;
    /** Raw file bytes; the C envelope separately uses canonical profile JSON. */
    profileSha256: string;
  };
}
type Store = Pick<ReturnType<typeof createRestrictedPartnerStore>,
  'consumerGuardReceiptIdentity' | 'readConsumerGuardReceipt' | 'compareAndSwapConsumerGuardReceipt'>;
type Row = Awaited<ReturnType<Store['readConsumerGuardReceipt']>>;
type Ledger = {
  schema: 'publication-main-source-operation/v1';
  operationId: string;
  binding: PublicationSourceBinding;
  profileSha256: string;
  state: 'OPENING' | 'OPEN' | 'DISPATCHING_UNKNOWN' | 'BOUND' | 'CURRENT' | 'UNKNOWN' | 'REVOKED';
  runId: number | null;
  attempt: number | null;
};
type Pin = { file: string; sha256: string; maximum: number; identity: string };
const identity = (s: Awaited<ReturnType<typeof lstat>>) =>
  [s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs].join(':');
/** Size checked before allocation/read; no symlink components or same-byte inode swaps. */
async function pinnedBytes(file: string, expected: string, maximum: number) {
  if (!hex(expected) || !path.isAbsolute(file) || path.normalize(file) !== file || await realpath(file) !== file) fail('PIN');
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o022) !== 0 ||
      before.size < 0 || before.size > maximum) fail('PIN_LIMIT');
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await fd.stat();
    if (!opened.isFile() || identity(before) !== identity(opened)) fail('SOURCE_CHANGED');
    const data = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < data.length) {
      const { bytesRead } = await fd.read(data, offset, Math.min(65536, data.length - offset), offset);
      if (!bytesRead) fail('SOURCE_CHANGED');
      offset += bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await fd.read(extra, 0, 1, offset)).bytesRead ||
        identity(before) !== identity(await fd.stat()) || identity(before) !== identity(await lstat(file)) ||
        await realpath(file) !== file || hash(data) !== expected) fail('SOURCE_CHANGED');
    return { data, identity: identity(before) };
  } finally { await fd.close(); }
}
const receipts = new WeakMap<object, { broker: RestrictedPublicationCISourceBroker; kind: 'ci' | 'definition'; value: Record<string, any> }>();
const brokers = new WeakSet<object>();
export function isRestrictedPublicationCISourceBroker(value: unknown): value is RestrictedPublicationCISourceBroker {
  return !!value && typeof value === 'object' && brokers.has(value);
}
export function readPublicationSourceReceipt(handle: object, broker: RestrictedPublicationCISourceBroker) {
  const r = receipts.get(handle);
  if (!r || r.broker !== broker) fail('PRIVATE_RECEIPT_REQUIRED');
  broker.assertCurrent();
  return structuredClone(r.value);
}

export class RestrictedPublicationCISourceBroker {
  private readonly profile: PinnedPublicationSourceWorker;
  private readonly expected: PublicationSourceBinding;
  private readonly nonce = randomBytes(32).toString('hex');
  private readonly started = performance.now();
  private readonly key: string;
  private row: Row;
  private ledger: Ledger;
  private pins: Pin[] = [];
  private child?: ChildProcess;
  private exited?: Promise<void>;
  private childClosed = false;
  private closed = false;
  private closing?: Promise<void>;
  private workerNonce: string | null = null;
  private sequence = 0;
  private definitionSequence = 0;
  private definitionHash?: string;
  private directoryPins = new Map<string, string>();
  private deadline?: ReturnType<typeof setTimeout>;
  private totalInput = 0;
  private totalOutput = 0;
  private buffers = new Map<number, Buffer>();
  private pending?: {
    sequence: number;
    command: string;
    timer: ReturnType<typeof setTimeout>;
    resolve: (value: Record<string, any>) => void;
    reject: (error: Error) => void;
  };
  private running = false;
  private definitionBusy = false;
  private ciReceipt?: object;
  private definitionReceipt?: object;
  private lifecycle?: { controller: ManagedPublicationController; handle: object };
  private unsubscribeLifecycle?: () => void;
  private lifecycleObserved = false;
  private missingDefinitionFact?: string;
  private auxiliary = new Map<ChildProcess, Promise<void>>();
  private constructor(
    private readonly store: Store,
    private readonly plugin: string,
    readonly operationId: string,
    profile: PinnedPublicationSourceWorker,
    expected: PublicationSourceBinding,
    private readonly currentBinding: () => PublicationSourceBinding,
  ) {
    this.expected = binding(expected);
    if (!hex(expected.accountId) || !hex(expected.deviceId) || !/^[A-Za-z0-9_-]{1,100}$/.test(operationId) ||
        typeof plugin !== 'string' || !plugin || Buffer.byteLength(plugin) > 512) fail('SCOPE');
    this.profile = structuredClone(profile);
    this.key = digest(['publication-main-source-operation/v1', operationId]);
    this.ledger = { schema: 'publication-main-source-operation/v1', operationId,
      binding: this.expected, profileSha256: digest(this.profile), state: 'OPENING', runId: null, attempt: null };
    brokers.add(this);
  }
  /** No restarts under the same original operation, even after a crash or a lost response. */
  static async startOwned(store: Store, plugin: string, operationId: string,
    profile: PinnedPublicationSourceWorker, expected: PublicationSourceBinding,
    currentBinding: () => PublicationSourceBinding) {
    const self = new RestrictedPublicationCISourceBroker(store, plugin, operationId, profile, expected, currentBinding);
    self.assertCurrent();
    if (await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key)) fail('OPERATION_ALREADY_CLAIMED');
    if (!await store.compareAndSwapConsumerGuardReceipt(plugin, expected.accountId, self.key, undefined, JSON.stringify(self.ledger))) fail('OPERATION_ALREADY_CLAIMED');
    try {
      self.row = await store.readConsumerGuardReceipt(plugin, expected.accountId, self.key);
      if (!self.row || self.row.revision !== 1 || self.row.payload !== JSON.stringify(self.ledger)) fail('LEDGER_CHANGED');
      await self.capturePins();
      self.assertCurrent();
      self.launch();
      await self.request('init', {}, 10000);
      await self.save('OPEN');
      return self;
    } catch (error) {
      await self.terminate('UNKNOWN');
      throw error;
    }
  }
  private async capturePins() {
    const p = this.profile;
    if (!p.files || Object.keys(p.files).length > 512 ||
        ![WORKER, 'bridge_core/__init__.py', 'bridge_core/worksheet_ci_guard_receipt.py'].every(x => hex(p.files[x]))) fail('SOURCE_PROFILE');
    if (!path.isAbsolute(p.root) || await realpath(p.root) !== p.root || !(await lstat(p.root)).isDirectory()) fail('SOURCE_PROFILE');
    let total = 0;
    const add = async (file: string, expected: string, maximum: number) => {
      const read = await pinnedBytes(file, expected, maximum);
      let parent = path.dirname(file);
      while (true) {
        const d = await lstat(parent);
        if (!d.isDirectory() || d.isSymbolicLink()) fail('PIN');
        const observed = [d.dev, d.ino, d.mode].join(':');
        const previous = this.directoryPins.get(parent);
        if (previous !== undefined && previous !== observed) fail('SOURCE_CHANGED');
        this.directoryPins.set(parent, observed);
        const next = path.dirname(parent);
        if (next === parent) break;
        parent = next;
      }
      this.pins.push({ file, sha256: expected, maximum, identity: read.identity });
      return read.data;
    };
    for (const [relative, sha256] of Object.entries(p.files)) {
      if (!relative || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').some(x => !x || x === '.' || x === '..')) fail('SOURCE_PROFILE');
      total += (await add(path.join(p.root, relative), sha256, 4 * TOTAL)).length;
      if (total > 64 * TOTAL) fail('SOURCE_BUDGET');
    }
    await add(p.python.path, p.python.sha256, 128 * TOTAL);
    await add(p.gh.path, p.gh.sha256, 128 * TOTAL);
    for (const context of [p.gh.homeDirectory, p.gh.configDirectory]) {
      if (typeof context !== 'string' || !path.isAbsolute(context) || await realpath(context) !== context ||
          !(await lstat(context)).isDirectory()) fail('GH_CONTEXT_REQUIRED');
    }
    if (p.definition) {
      const d = p.definition;
      if (!hex(p.files['scripts/__init__.py'])) fail('DEFINITION_SOURCE_PINS');
      await add(path.join(d.monitorRoot, 'monitor/publication_definition_receipts.py'), d.monitorSha256, TOTAL);
      const raw = await add(d.profilePath, d.profileSha256, FRAME - 1);
      const profile = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(raw));
      if (!object(profile) || profile.sourceRoot !== p.root || profile.monitorRoot !== d.monitorRoot) fail('DEFINITION_PROFILE');
      if (!object(profile.sourceFiles) || Object.keys(profile.sourceFiles).length === 0 ||
          Object.entries(profile.sourceFiles).some(([file, expected]) => p.files[file] !== expected)) fail('DEFINITION_SOURCE_PINS');
      this.definitionHash = digest(profile);
    }
  }
  private async verifyPins() {
    this.assertCurrent();
    for (const [p, expected] of this.directoryPins) {
      const d = await lstat(p);
      if (!d.isDirectory() || d.isSymbolicLink() || [d.dev, d.ino, d.mode].join(':') !== expected) fail('SOURCE_CHANGED');
    }
    for (const p of this.pins) {
      const read = await pinnedBytes(p.file, p.sha256, p.maximum);
      if (read.identity !== p.identity) fail('SOURCE_CHANGED');
    }
    this.assertCurrent();
  }
  assertCurrent() {
    if (this.closed || performance.now() - this.started >= 60000) {
      this.failClosed(); fail('CLOSED');
    }
    try {
      if (canonical(binding(this.currentBinding())) !== canonical(this.expected)) fail('OWNER_CHANGED');
      if (this.childClosed) fail('CHILD_EXITED');
    } catch (error) { this.failClosed(); throw error; }
  }
  matchesOwner(store: object, plugin: string, account: string, generation: string) {
    this.assertCurrent();
    return store === this.store.consumerGuardReceiptIdentity && plugin === this.plugin &&
      account === this.expected.accountId && generation === this.expected.generation;
  }
  private invalidate() {
    this.closed = true;
    this.unsubscribeLifecycle?.(); this.unsubscribeLifecycle = undefined;
    if (this.deadline) clearTimeout(this.deadline);
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(Error('PUBLICATION_SOURCE_CLOSED'));
      this.pending = undefined;
    }
    for (const child of this.auxiliary.keys()) child.kill('SIGTERM');
  }
  private failClosed() { void this.terminate('UNKNOWN').catch(() => {}); }
  private output(fd: 7 | 9): Writable {
    const stream = (this.child?.stdio as Array<Readable | Writable | null | undefined> | undefined)?.[fd];
    if (!stream || !('write' in stream)) fail('CHANNEL_CLOSED');
    return stream as Writable;
  }
  private launch() {
    this.assertCurrent();
    const p = this.profile;
    const argv = ['-I', '-B', path.join(p.root, WORKER), '--session-nonce', this.nonce,
      '--gh-executable', p.gh.path, '--gh-sha256', p.gh.sha256];
    if (p.definition) argv.push('--monitor-root', p.definition.monitorRoot, '--monitor-sha256', p.definition.monitorSha256,
      '--definition-profile', p.definition.profilePath, '--definition-profile-sha256', p.definition.profileSha256);
    const child = spawn(p.python.path, argv, { cwd: p.root,
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', PYTHONDONTWRITEBYTECODE: '1', GH_PROMPT_DISABLED: '1',
        GH_NO_UPDATE_NOTIFIER: '1', GH_NO_EXTENSION_UPDATE_NOTIFIER: '1', GH_TELEMETRY: '0',
        HOME: p.gh.homeDirectory, GH_CONFIG_DIR: p.gh.configDirectory },
      stdio: ['ignore', 'pipe', 'pipe', 'ignore', 'ignore', 'ignore', 'ignore', 'pipe', 'pipe',
        p.definition ? 'pipe' : 'ignore', p.definition ? 'pipe' : 'ignore'] });
    this.child = child;
    this.exited = new Promise<void>(resolve => {
      child.once('error', () => { this.failClosed(); });
      child.once('close', () => { this.childClosed = true; this.failClosed(); resolve(); });
    });
    for (const i of [1, 2, 8, ...(p.definition ? [10] : [])]) {
      (child.stdio[i] as Readable).on('data', (data: Buffer) => this.receive(i, data));
      (child.stdio[i] as Readable).on('error', () => this.failClosed());
    }
    for (const i of [7, ...(p.definition ? [9] : [])])
      (child.stdio[i] as Writable).on('error', () => this.failClosed());
    for (const i of [8, ...(p.definition ? [10] : [])])
      (child.stdio[i] as Readable).on('end', () => { if (!this.closed) this.failClosed(); });
    this.deadline = setTimeout(() => this.failClosed(), Math.max(1, 60000 - (performance.now() - this.started)));
  }
  private receive(fd: number, data: Buffer) {
    if (this.closed) return;
    try {
      this.assertCurrent();
      this.totalInput += data.length;
      if (this.totalInput > TOTAL || (fd < 3 && data.length > 0)) fail('OUTPUT_LIMIT');
      if (fd < 3) return;
      const old = this.buffers.get(fd) ?? Buffer.alloc(0);
      if (old.length + data.length > FRAME) fail('FRAME_LIMIT');
      const buffer = Buffer.concat([old, data]);
      const end = buffer.indexOf(10);
      if (end < 0) { this.buffers.set(fd, buffer); return; }
      if (end !== buffer.length - 1 || end === 0) fail('UNSOLICITED_FRAME');
      this.buffers.delete(fd);
      const frame = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, end)));
      if (fd === 10) {
        if (this.definitionBusy) fail('DEFINITION_OVERLAP');
        this.definitionBusy = true;
        void this.definitionQuery(frame).catch(() => this.failClosed()).finally(() => { this.definitionBusy = false; });
        return;
      }
      const pending = this.pending;
      keys(frame, 'schema,session_nonce,worker_nonce,sequence,owner_binding,operation_id,ok,state,code,result');
      if (!pending || frame.schema !== SCHEMA || frame.session_nonce !== this.nonce ||
          frame.sequence !== pending.sequence || frame.operation_id !== this.operationId ||
          canonical(frame.owner_binding) !== canonical(this.expected) || !hex(frame.worker_nonce) ||
          (this.workerNonce !== null && frame.worker_nonce !== this.workerNonce) ||
          typeof frame.ok !== 'boolean') fail('RESPONSE_BINDING');
      if (!frame.ok || frame.code !== null) fail('WORKER_DENIED');
      const states: Record<string, string[]> = { init: ['OPEN'], 'ci.begin': ['PENDING'], 'ci.bind': ['BOUND'],
        'ci.verify': ['VERIFYING'], 'ci.current': ['VERIFYING', 'CURRENT'], 'definition.begin': ['PENDING'],
        'definition.verify': ['VERIFYING'], 'definition.current': ['VERIFYING', 'CURRENT'] };
      if (!states[pending.command]?.includes(frame.state)) fail('RESPONSE_STATE');
      this.workerNonce = frame.worker_nonce;
      clearTimeout(pending.timer); this.pending = undefined;
      pending.resolve(frame);
    } catch { this.failClosed(); }
  }
  private async request(command: string, payload: Record<string, unknown>, timeout = 30000) {
    this.assertCurrent();
    if (this.pending || this.sequence >= 512) fail('REQUEST_STATE');
    await this.verifyPins();
    await this.verifyLedger();
    this.assertCurrent();
    if (this.pending) fail('REQUEST_STATE');
    const sequence = ++this.sequence;
    const raw = Buffer.from(canonical({ schema: SCHEMA, session_nonce: this.nonce, worker_nonce: this.workerNonce,
      sequence, owner_binding: this.expected, operation_id: this.operationId, command, payload }) + '\n');
    if (raw.length > FRAME || (this.totalOutput += raw.length) > TOTAL) fail('FRAME_LIMIT');
    const response = await new Promise<Record<string, any>>((resolve, reject) => {
      const timer = setTimeout(() => this.failClosed(), Math.min(timeout, Math.max(1, 60000 - (performance.now() - this.started))));
      this.pending = { sequence, command, timer, resolve, reject };
      this.output(7).write(raw, error => { if (error) this.failClosed(); });
    });
    // Deferred reads can straddle a durable revoke or same-byte source replacement.
    await this.verifyPins();
    await this.verifyLedger();
    return response;
  }
  private async verifyLedger() {
    this.assertCurrent();
    const current = await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key);
    this.assertCurrent();
    if (!current || !this.row || current.revision !== this.row.revision || current.payload !== this.row.payload ||
        current.payload !== JSON.stringify(this.ledger)) fail('LEDGER_CHANGED');
  }
  private async save(state: Ledger['state'], runId = this.ledger.runId, attempt = this.ledger.attempt, terminalWrite = false) {
    if (!terminalWrite) this.assertCurrent();
    const next: Ledger = { ...this.ledger, state, runId, attempt };
    const current = await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key);
    if (!terminalWrite) this.assertCurrent();
    if (!current || !this.row || current.revision !== this.row.revision || current.payload !== this.row.payload ||
        !await this.store.compareAndSwapConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key, this.row, JSON.stringify(next))) fail('LEDGER_CHANGED');
    const written = await this.store.readConsumerGuardReceipt(this.plugin, this.expected.accountId, this.key);
    if (!written || written.revision !== this.row.revision + 1 || written.payload !== JSON.stringify(next)) fail('LEDGER_CHANGED');
    this.row = written;
    this.ledger = next;
    if (!terminalWrite) this.assertCurrent();
  }
  private async exclusive<T>(use: () => Promise<T>) {
    this.assertCurrent();
    if (this.running) fail('BUSY');
    this.running = true;
    try { return await use(); }
    catch (error) { await this.terminate('UNKNOWN'); throw error; }
    finally { this.running = false; }
  }
  /** Real original controlled POST + exact returned run readback. The caller is Main's
   * original approval owner; absent/currently revoked approval never dispatches. No run-ID setter.
   * GitHub return_run_details is the official dispatch response, never a latest-run search.
   */
  async dispatchOriginalCI(head: string, workflowSha256: string, assertDispatchApproved: () => void) {
    return this.exclusive(async () => {
      if (!/^[a-f0-9]{40}$/.test(head) || !hex(workflowSha256) || typeof assertDispatchApproved !== 'function' || this.ledger.state !== 'OPEN') fail('DISPATCH_INPUT');
      assertDispatchApproved();
      const begin = await this.request('ci.begin', { head, workflow_sha256: workflowSha256, ttl_seconds: 60 });
      keys(begin.result, 'dispatch_inputs');
      const inputs = begin.result.dispatch_inputs;
      keys(inputs, 'execution_mode,probe_operation_id');
      if (inputs.execution_mode !== 'native-guard-probe' || !hex(inputs.probe_operation_id)) fail('DISPATCH_INPUT');
      const user = await this.official('GET', '/user', undefined, assertDispatchApproved);
      const ref = await this.official('GET', '/repos/' + REPOSITORY + '/git/ref/heads/main', undefined, assertDispatchApproved);
      if (user.login !== 'albertyangchao' || ref.object?.sha !== head) fail('DISPATCH_SOURCE');
      // Verify the approved probe workflow at that exact commit before the POST.
      // A matching branch head alone must not dispatch an older publish-only workflow.
      const workflow = await this.official('GET', '/repos/' + REPOSITORY + '/contents/' + WORKFLOW + '?ref=' + head,
        undefined, assertDispatchApproved);
      if (workflow.type !== 'file' || workflow.path !== WORKFLOW || workflow.encoding !== 'base64' ||
          typeof workflow.content !== 'string' || !Number.isSafeInteger(workflow.size) ||
          workflow.size <= 0 || workflow.size > FRAME) fail('DISPATCH_WORKFLOW');
      const encoded = workflow.content.replace(/\n/g, '');
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) fail('DISPATCH_WORKFLOW');
      const bytes = Buffer.from(encoded, 'base64');
      if (bytes.length !== workflow.size || bytes.toString('base64') !== encoded || hash(bytes) !== workflowSha256)
        fail('DISPATCH_WORKFLOW');
      // Durable once claim precedes the sole external effect. Every error remains UNKNOWN.
      await this.save('DISPATCHING_UNKNOWN');
      assertDispatchApproved();
      const dispatched = await this.official('POST', '/repos/' + REPOSITORY + '/actions/workflows/publish-worksheet-html.yml/dispatches',
        { ref: 'main', inputs, return_run_details: true }, assertDispatchApproved);
      const id = dispatched.workflow_run_id;
      if (!positive(id) || dispatched.run_url !== 'https://api.github.com/repos/' + REPOSITORY + '/actions/runs/' + id ||
          dispatched.html_url !== 'https://github.com/' + REPOSITORY + '/actions/runs/' + id) fail('DISPATCH_UNKNOWN');
      // Retain the original returned ID even if the independent readback is lost.
      await this.save('DISPATCHING_UNKNOWN', id, null);
      const run = await this.official('GET', '/repos/' + REPOSITORY + '/actions/runs/' + id, undefined, assertDispatchApproved);
      if (run.id !== id || run.repository?.full_name !== REPOSITORY || run.head_sha !== head || run.head_branch !== 'main' ||
          run.path !== WORKFLOW || run.event !== 'workflow_dispatch' || run.run_attempt !== 1) fail('DISPATCH_READBACK');
      await this.request('ci.bind', { run_id: id, attempt: 1 });
      await this.save('BOUND', id, 1);
      return Object.freeze({ runId: id, attempt: 1 });
    });
  }
  private async official(method: 'GET' | 'POST', endpoint: string, body: unknown, approved: () => void) {
    await this.verifyPins(); await this.verifyLedger(); approved(); this.assertCurrent();
    const args = ['api', '--hostname', 'github.com', '--method', method, endpoint,
      '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2026-03-10'];
    if (body !== undefined) args.push('--input', '-');
    const child = spawn(this.profile.gh.path, args, { cwd: this.profile.root,
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', GH_PROMPT_DISABLED: '1', GH_PAGER: 'cat',
        GH_NO_UPDATE_NOTIFIER: '1', GH_NO_EXTENSION_UPDATE_NOTIFIER: '1', GH_TELEMETRY: '0',
        HOME: this.profile.gh.homeDirectory, GH_CONFIG_DIR: this.profile.gh.configDirectory },
      stdio: ['pipe', 'pipe', 'pipe'] });
    this.auxiliary.set(child, new Promise<void>(resolve => child.once('close', () => resolve())));
    const parts: Buffer[] = []; let size = 0, errors = 0, failure: Error | undefined;
    const stop = (code: string) => { failure ??= Error('PUBLICATION_SOURCE_' + code); child.kill('SIGTERM'); };
    const timer = setTimeout(() => stop('OFFICIAL_TIMEOUT'), 10000);
    const kill = setTimeout(() => { stop('OFFICIAL_TIMEOUT'); child.kill('SIGKILL'); }, 10500);
    try {
      const raw = await new Promise<Buffer>((resolve, reject) => {
        child.stdout.on('data', (b: Buffer) => { size += b.length; if (size > 2 * TOTAL) stop('OFFICIAL_LIMIT'); else parts.push(b); });
        child.stderr.on('data', (b: Buffer) => { errors += b.length; if (errors > FRAME) stop('OFFICIAL_LIMIT'); });
        child.on('error', () => stop('OFFICIAL_UNAVAILABLE'));
        child.on('close', code => code === 0 && !failure ? resolve(Buffer.concat(parts)) : reject(failure ?? Error('PUBLICATION_SOURCE_OFFICIAL_UNAVAILABLE')));
        child.stdin.on('error', () => stop('OFFICIAL_UNAVAILABLE'));
        child.stdin.end(body === undefined ? undefined : canonical(body));
      });
      this.assertCurrent(); approved(); await this.verifyPins();
      // These fixed endpoints return small single objects, never arbitrary lists/logs.
      const value = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(raw));
      if (!object(value)) fail('OFFICIAL_SCHEMA');
      return value;
    } finally { clearTimeout(timer); clearTimeout(kill); this.auxiliary.delete(child); }
  }
  async inspectCI() {
    return this.exclusive(async () => {
      if (!this.ciReceipt) {
        if (this.ledger.state !== 'BOUND') fail('RUN_NOT_BOUND');
        await this.request('ci.verify', {});
      }
      const reply = await this.pollCurrent('ci.current');
      const value = reply.result;
      if (!object(value) || value.schema !== 'core-worksheet-owner-observation/v1' || value.operation_id !== this.operationId ||
          canonical(value.owner_binding) !== canonical([this.expected.accountId, this.expected.deviceId, this.expected.bootId, this.expected.ownerEpoch, this.expected.generation]) ||
          value.run_id !== this.ledger.runId || value.attempt !== this.ledger.attempt ||
          value.repository !== REPOSITORY || value.workflow !== WORKFLOW || value.state !== 'NATIVE_NAMESPACE_DENIED' ||
          !positive(value.job_id) || !positive(value.check_run_id) || value.check_run_url !==
            'https://api.github.com/repos/' + REPOSITORY + '/check-runs/' + value.check_run_id) fail('CI_BINDING');
      await this.save('CURRENT');
      this.assertCurrent();
      return this.ciReceipt = this.receipt('ci', value);
    });
  }
  private async pollCurrent(command: 'ci.current' | 'definition.current') {
    const until = Math.min(this.started + 60000, performance.now() + 30000);
    while (true) {
      const reply = await this.request(command, {}, Math.max(1, until - performance.now()));
      if (reply.state === 'CURRENT') return reply;
      if (performance.now() >= until) fail('VERIFY_TIMEOUT');
      // Only retry an explicit VERIFYING response. A deferred current owns its one request.
      await new Promise<void>(resolve => setTimeout(resolve, 100));
      this.assertCurrent();
    }
  }
  attachOwnedLifecycle(handle: object, controller: ManagedPublicationController) {
    this.assertCurrent();
    if (this.lifecycle) fail('LIFECYCLE_ALREADY_BOUND');
    const fact = readManagedLifecycleReceipt(handle, controller);
    if (fact.phase !== 'LOADED' || fact.operationId !== this.operationId || canonical(fact.binding) !== canonical(this.expected)) fail('LIFECYCLE_BINDING');
    this.lifecycle = { controller, handle };
    this.unsubscribeLifecycle = controller.onSourceInvalidated(() => this.failClosed());
  }
  private async definitionQuery(frame: Record<string, any>) {
    keys(frame, 'schema,sessionId,seq,nonce,binding,operationId,profileSha256,method,args');
    this.assertCurrent();
    if (frame.schema !== DEFINITION_SCHEMA || frame.sessionId !== this.workerNonce || frame.seq !== this.definitionSequence + 1 ||
        !hex(frame.nonce) || canonical(frame.binding) !== canonical(this.expected) || frame.operationId !== this.operationId ||
        frame.profileSha256 !== this.definitionHash || !object(frame.args)) fail('DEFINITION_BINDING');
    this.definitionSequence = frame.seq;
    let value: Record<string, unknown>;
    let ok = true;
    if (frame.method === 'lifecycle' && Object.keys(frame.args).length === 0 && this.lifecycle) {
      // Held private Main fact, independently rechecked against its original durable transition.
      await this.lifecycle.controller.verifyLifecycleReceipt(this.lifecycle.handle);
      value = { ...readManagedLifecycleReceipt(this.lifecycle.handle, this.lifecycle.controller) };
      this.lifecycleObserved = true;
    } else {
      // Original resident/legacy/namespace owners have no enrolled producer in the frozen
      // source inputs. Explicit CODE refusal; never manufacture a census from profile roles.
      ok = false;
      const codes: Record<string, string> = { census: 'OWNER_CENSUS_UNAVAILABLE', member: 'OWNER_MEMBER_UNAVAILABLE',
        namespace: 'NAMESPACE_OWNER_UNAVAILABLE', fence: 'OWNER_FENCE_UNAVAILABLE', current: 'OWNER_CURRENT_UNAVAILABLE' };
      value = { code: Object.hasOwn(codes, frame.method) ? codes[frame.method] : 'LIFECYCLE_UNAVAILABLE' };
      this.missingDefinitionFact = Object.hasOwn(codes, frame.method) ? frame.method : 'lifecycle';
    }
    this.assertCurrent();
    const { method: _method, args: _args, ...echo } = frame;
    const raw = Buffer.from(canonical({ ...echo, ok, value }) + '\n');
    if (raw.length > FRAME || (this.totalOutput += raw.length) > TOTAL) fail('FRAME_LIMIT');
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(Error('PUBLICATION_SOURCE_DEFINITION_TIMEOUT')), 1000);
      this.output(9).write(raw, error => { clearTimeout(timer); error ? reject(error) : resolve(); });
    });
  }
  async inspectDefinition() {
    return this.exclusive(async () => {
      if (!this.profile.definition || !this.lifecycle) fail('DEFINITION_UNAVAILABLE');
      if (!this.definitionReceipt) {
        await this.request('definition.begin', { ttl_seconds: 60 });
        await this.request('definition.verify', {});
      }
      const reply = await this.pollCurrent('definition.current');
      const value = reply.result;
      if (!object(value) || value.schema !== 'publication-definition-receipt/v1' ||
          value.operationId !== this.operationId || canonical(value.binding) !== canonical(this.expected) ||
          value.profileSha256 !== this.definitionHash || value.releaseGeneration !== this.expected.generation ||
          value.scope !== 'REGISTERED_DEFINITION_SOURCES_ONLY') fail('DEFINITION_BINDING');
      this.assertCurrent();
      return this.definitionReceipt = this.receipt('definition', value);
    });
  }
  private receipt(kind: 'ci' | 'definition', value: Record<string, any>) {
    const handle = Object.freeze(Object.create(null));
    receipts.set(handle, { broker: this, kind, value: structuredClone(value) });
    return handle;
  }
  /** Async freshness must complete before effect approval; sync reads never renew a lease. */
  async current(handle: object) {
    const r = receipts.get(handle);
    if (!r || r.broker !== this) fail('PRIVATE_RECEIPT_REQUIRED');
    return this.exclusive(async () => {
      const reply = await this.pollCurrent(r.kind === 'ci' ? 'ci.current' : 'definition.current');
      if (canonical(reply.result) !== canonical(r.value)) fail('CURRENT_CHANGED');
      this.assertCurrent();
      return structuredClone(r.value);
    });
  }
  /** Local handles close synchronously. EOF revokes both Python sources and owned readers;
   * allow B's 3.25s cleanup, then kill/reap only the actual ChildProcess we own.
   */
  revoke(): Promise<void> { return this.terminate('REVOKED'); }
  diagnostics() {
    return Object.freeze({ closed: this.closed, state: this.ledger.state,
      ownedLifecycleObserved: this.lifecycleObserved, missingDefinitionFact: this.missingDefinitionFact ?? null,
      runId: this.ledger.runId, attempt: this.ledger.attempt });
  }
  private terminate(state: 'UNKNOWN' | 'REVOKED'): Promise<void> {
    this.invalidate();
    if (this.closing) return this.closing;
    this.closing = (async () => {
      let cleanupUnknown = false;
      const child = this.child;
      // Close both owners immediately even if an unrelated owned read cannot be reaped.
      if (child) {
        try { this.output(7).end(); } catch { cleanupUnknown = true; }
        if (this.profile.definition) {
          try { this.output(9).end(); } catch { cleanupUnknown = true; }
        }
      }
      const auxiliary = [...this.auxiliary.entries()];
      for (const [process, done] of auxiliary) {
        if (!await waitForExit(done, 500)) {
          process.kill('SIGKILL');
          if (!await waitForExit(done, 1000)) cleanupUnknown = true;
        }
      }
      if (child) {
        if (!await waitForExit(this.exited!, 5000)) {
          child.kill('SIGTERM');
          if (!await waitForExit(this.exited!, 500)) {
            child.kill('SIGKILL');
            if (!await waitForExit(this.exited!, 1000)) cleanupUnknown = true;
          }
        }
      }
      // A possible dispatch stays DISPATCHING_UNKNOWN; shutdown cannot turn it into retryable.
      const terminal = this.ledger.state === 'DISPATCHING_UNKNOWN' ? 'DISPATCHING_UNKNOWN' : state;
      try { await this.save(terminal, this.ledger.runId, this.ledger.attempt, true); }
      catch { /* Preserve original row on owner change/CAS failure; original operation stays consumed. */ }
      if (cleanupUnknown) fail('CLEANUP_UNKNOWN');
    })();
    return this.closing;
  }
}
