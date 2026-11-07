import {
  ManagedPublicationController,
  type PublisherReleaseSource,
} from './restrictedPublicationManagedController.js';
/** Main-owned canonical transport. Root child packets are candidates, never authority. */
import { spawn } from 'node:child_process';
import {
  open,
  lstat,
  realpath,
  mkdir,
  writeFile,
  readFile,
  readdir,
  rename,
  unlink,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { publicationPython, publicationManagedEntryPython } from './restrictedPublicationPython.js';
import {
  isConsumerGuardCoverageAuthority,
  type ConsumerGuardCoverageAuthority,
  type ManagedPublicationJob,
} from './restrictedPublicationConsumerGuardAuthority.js';
import {
  canonical,
  digest,
  wireBinding,
  publicMarker,
  canonicalSidecar,
  releasePair,
  releaseId,
  orderedPair,
  nativeWireSchema,
  nativeDispatcher,
  publicationEffects,
  parseNativeFrame,
} from './restrictedPublicationProtocol.js';
import type {
  NativePublisherRuntime,
  NativePublicationRecord,
  NativePublicationControl,
  NativePublicationReceipt,
  PublicationEffect,
} from './restrictedPartnerPublication.js';
const entry = 'scripts/publish_generic_html_direct.py';
const sha = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex');
const denied = (): never => {
  throw Error('NATIVE_PUBLISHER_CALLER_DENIED');
};
/** Main-private deployment registration, not an IPC/Node/model argument or a public Host API. */
export interface RegisteredPublicationRoot {
  root: string;
  artifactRoot: string;
  queueRoot: string;
  dispatchRoot: string;
  publicOrigin: string;
  sourceIdentity: string;
  files: Record<string, string>;
  python: { path: string; sha256: string };
  /** Existing canonical consumer owner must supply actual current guarded-runtime evidence.
   * File pinning or a public Host version alone never proves older live consumers guarded. */
  assertConsumerGuards(): Promise<void>;
  /** Main-private authority, not an Agent proof/boolean or the preflight callback above. */
  consumerCoverage: ConsumerGuardCoverageAuthority;
  consumerRootIdentity: string;
  /** Optional until actual managed install/enrollment is approved. Never populated from IPC. */
  managedPublisher?: { controller: ManagedPublicationController; source: PublisherReleaseSource };
}
/** No supported installed root/consumer attestation is currently registered. No production enqueue. */
export const supportedPublicationRoot: RegisteredPublicationRoot | undefined = undefined;
type Result = { stdout: Buffer };
interface MainTransport {
  execute(
    executable: '/usr/bin/ssh' | '/usr/bin/scp',
    args: string[],
    current: () => void,
  ): Promise<Result>;
  readback(url: string, current: () => void): Promise<Buffer>;
}
const transport: MainTransport = {
  execute: (executable, args, current) =>
    boundedProcess(executable, args, undefined, undefined, current, 120000, 65536),
  async readback(url, current) {
    current();
    const abort = new AbortController(),
      timer = setTimeout(() => abort.abort(), 15000);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      const r = await fetch(url, { redirect: 'error', signal: abort.signal });
      current();
      if (r.status !== 200 || !r.body) denied();
      reader = r.body!.getReader();
      const chunks: Uint8Array[] = [],
        limit = 8 * 1024 * 1024;
      let size = 0;
      while (true) {
        current();
        const part = await reader.read();
        current();
        if (part.done) break;
        size += part.value.length;
        if (size > limit) denied();
        chunks.push(part.value);
      }
      return Buffer.concat(chunks);
    } finally {
      clearTimeout(timer);
      void reader?.cancel().catch(() => {});
    }
  },
};
function boundedProcess(
  executable: string,
  args: string[],
  input: unknown,
  options: { cwd: string; env: NodeJS.ProcessEnv } | undefined,
  current: () => void,
  deadline = 10000,
  limit = 65536,
  managedJob?: ManagedPublicationJob,
  createChild?: () => ReturnType<typeof spawn>,
): Promise<Result> {
  current();
  return new Promise((resolve, reject) => {
    let ended = false;
    const chunks: Buffer[] = [];
    let size = 0;
    const child = createChild
      ? createChild()
      : spawn(executable, args, {
          ...options,
          stdio: managedJob
            ? ['pipe', 'pipe', 'pipe', 'ignore', 'ignore', 'pipe', 'pipe']
            : ['pipe', 'pipe', 'pipe'],
        });
    const finish = (error?: unknown) => {
      if (ended) return;
      ended = true;
      clearTimeout(timer);
      child.stdin?.destroy();
      if (error) {
        managedJob?.revoke();
        child.kill();
        reject(Error('NATIVE_MAIN_OPERATION_UNKNOWN'));
      } else {
        try {
          current();
          resolve({ stdout: Buffer.concat(chunks) });
        } catch {
          reject(Error('NATIVE_MAIN_OPERATION_UNKNOWN'));
        }
      }
    };
    const timer = setTimeout(() => finish(Error('TIMEOUT')), deadline);
    try {
      managedJob?.attach(child);
    } catch (error) {
      finish(error);
      return;
    }
    child.stdin?.on('error', () => {});
    child.stderr?.on('data', () => {});
    child.stdout?.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) finish(Error('LIMIT'));
      else chunks.push(chunk);
    });
    child.on('error', finish);
    child.on('close', (code) => {
      if (!managedJob) finish(code === 0 ? undefined : Error('EXIT'));
      else
        void managedJob.finishProcess(code === 0).then(
          () => finish(),
          (error) => finish(error),
        );
    });
    child.stdin?.end(input === undefined ? undefined : JSON.stringify(input));
  });
}
/** A synthetic transport is injectable only in Main unit tests, never from a plugin request. */
export function controlledPublicationRuntime(
  pin: RegisteredPublicationRoot,
  guards: { effectCurrent(): void; readCurrent(): void },
  io: MainTransport = transport,
): NativePublisherRuntime {
  if (
    !pin ||
    !path.isAbsolute(pin.root) ||
    !path.isAbsolute(pin.artifactRoot) ||
    !path.isAbsolute(pin.dispatchRoot) ||
    !path.isAbsolute(pin.queueRoot) ||
    typeof pin.assertConsumerGuards !== 'function' ||
    !isConsumerGuardCoverageAuthority(pin.consumerCoverage) ||
    !/^[a-f0-9]{64}$/.test(pin.consumerRootIdentity) ||
    !/^[a-f0-9]{64}$/.test(pin.sourceIdentity) ||
    !pin.files[entry] ||
    !pin.files['bridge_core/native_html_release.py'] ||
    !path.isAbsolute(pin.python.path) ||
    !/^[a-f0-9]{64}$/.test(pin.python.sha256)
  )
    denied();
  const origin = new URL(pin.publicOrigin);
  if (
    origin.origin !== pin.publicOrigin ||
    origin.protocol !== 'https:' ||
    origin.username ||
    origin.password ||
    origin.port
  )
    denied();
  const files = Object.freeze({ ...pin.files });
  const managedPublisher = pin.managedPublisher;
  const managedController = managedPublisher?.controller;
  const managedSourceDigest = managedPublisher ? digest(managedPublisher.source) : undefined;
  if (managedController && !(managedController instanceof ManagedPublicationController)) denied();
  const coverage = pin.consumerCoverage,
    coverageRoot = pin.consumerRootIdentity;
  const rootDefinition = () =>
    digest([
      pin.sourceIdentity,
      pin.root,
      pin.artifactRoot,
      pin.queueRoot,
      pin.dispatchRoot,
      pin.publicOrigin,
      files,
      pin.python,
    ]);
  const registeredDefinition = rootDefinition();
  const coverageBindingCurrent = () => {
    if (
      pin.managedPublisher !== managedPublisher ||
      pin.managedPublisher?.controller !== managedController ||
      (managedPublisher && digest(managedPublisher.source) !== managedSourceDigest)
    )
      denied();
    managedController?.assertCurrent(pin.root);
    if (
      rootDefinition() !== registeredDefinition ||
      pin.consumerCoverage !== coverage ||
      pin.consumerRootIdentity !== coverageRoot
    )
      denied();
    coverage.assertRootBinding(coverageRoot, registeredDefinition);
  };
  const readFixed = async (root: string, rel: string, limit = 12 * 1024 * 1024) => {
    if (
      !rel ||
      rel.includes('\\') ||
      rel.split('/').some((x) => !x || x === '.' || x === '..') ||
      (await realpath(root)) !== root
    )
      denied();
    let parent = root;
    for (const part of ['', ...rel.split('/').slice(0, -1)]) {
      parent = part ? path.join(parent, part) : parent;
      const s = await lstat(parent);
      if (
        s.isSymbolicLink() ||
        !s.isDirectory() ||
        (process.getuid && s.uid !== process.getuid()) ||
        s.mode & 0o022
      )
        denied();
    }
    const fd = await open(path.join(root, rel), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await fd.stat();
      if (
        !before.isFile() ||
        before.nlink !== 1 ||
        (process.getuid && before.uid !== process.getuid()) ||
        before.mode & 0o022 ||
        before.size > limit
      )
        denied();
      const bytes = await fd.readFile();
      const after = await fd.stat();
      if (
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs
      )
        denied();
      return bytes;
    } finally {
      await fd.close();
    }
  };
  const verifyFiles = async () => {
    guards.readCurrent();
    const required = [
      'scripts/publish_worksheet_html.py',
      'bridge_core/publish_html.py',
      'bridge_core/report_publish_queue.py',
      'bridge_core/html_contract.py',
      'bridge_core/research_artifacts.py',
      'config/html_ui_contract.json',
      'config/reserved_html_owners.json',
      'config/bridge_shell_builders.json',
      'config/artifact_publish_policy.json',
    ];
    const local = await readdir(path.join(pin.root, 'bridge_core'));
    guards.readCurrent();
    if (
      local.length > 512 ||
      [...required, ...local.filter((n) => n.endsWith('.py')).map((n) => 'bridge_core/' + n)].some(
        (rel) => !Object.hasOwn(files, rel),
      )
    )
      denied();
    for (const [rel, expected] of Object.entries(files)) {
      if (!/^[a-f0-9]{64}$/.test(expected) || sha(await readFixed(pin.root, rel)) !== expected)
        denied();
      guards.readCurrent();
    }
    if (
      (await realpath(pin.python.path)) !== pin.python.path ||
      sha(await readFile(pin.python.path)) !== pin.python.sha256
    )
      denied();
    guards.readCurrent();
  };
  const env: NodeJS.ProcessEnv = {
    PATH: '/usr/bin:/bin',
    LANG: 'en_US.UTF-8',
    BRIDGE_REPORTS_LOCAL_DIR: pin.artifactRoot,
    BRIDGE_REPORT_QUEUE_DIR: pin.queueRoot,
    BRIDGE_REPORT_SYNC_AFTER_PUBLISH: '1',
    PYTHONDONTWRITEBYTECODE: '1',
  };
  const pure = async (
    operation: string,
    a?: NativePublicationRecord,
    extra: Record<string, unknown> = {},
    readonly = false,
    coverageCurrent?: () => void,
    managedJob?: ManagedPublicationJob,
  ) => {
    const current = () => {
      (readonly ? guards.readCurrent : guards.effectCurrent)();
      coverageCurrent?.();
    };
    await verifyFiles();
    current();
    const launch =
      managedJob && pin.managedPublisher
        ? await pin.managedPublisher.controller.prepareOwnedChild(
            managedJob,
            pin.managedPublisher.source,
            { operation: 'stage', artifacts: pin.artifactRoot, queue: pin.queueRoot },
          )
        : undefined;
    const result = await boundedProcess(
      pin.python.path,
      ['-I', '-c', publicationPython, pin.root],
      {
        operation,
        ...(a ? { binding: wireBinding(a), artifactRoot: pin.artifactRoot } : {}),
        ...(managedJob ? { managedExpected: managedPublicationExpected(managedJob) } : {}),
        ...extra,
      },
      {
        cwd: pin.root,
        env: managedJob
          ? { ...env, BRIDGE_CONSUMER_CONTROL_READ_FD: '5', BRIDGE_CONSUMER_CONTROL_WRITE_FD: '6' }
          : env,
      },
      current,
      10000,
      65536,
      managedJob,
      launch,
    );
    current();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout));
  };
  const verify = async () => {
    await verifyFiles();
    await managedController?.verifyCurrent(pin.root);
    await pin.assertConsumerGuards();
    await coverage.readCurrent(coverageRoot, coverage.freshChallenge(coverageRoot));
    coverageBindingCurrent();
    guards.readCurrent();
    // A legacy root can write before it ever reads a control FD. Refuse it BEFORE launching a stage job.
    // This is a pinned source ABI prerequisite, never runtime coverage evidence or a READY issuer.
    const managed = await boundedProcess(
      pin.python.path,
      [
        '-I',
        '-c',
        'import sys,json;sys.path.insert(0,sys.argv[1]);from bridge_core.publication_consumer_controller import main_job_contract;print(json.dumps(main_job_contract()))',
        pin.root,
      ],
      { operation: 'managed-contract' },
      { cwd: pin.root, env },
      guards.readCurrent,
      10000,
      65536,
    );
    guards.readCurrent();
    const managedContract = parseNativeFrame(
      new TextDecoder('utf-8', { fatal: true }).decode(managed.stdout),
    );
    if (
      canonical(managedContract) !==
      canonical({
        schema: 'publication-managed-job/v1',
        nativeQueueIO: 'main-only',
        controlReadFd: 5,
        controlWriteFd: 6,
      })
    )
      denied();
    const c = await pure('contract', undefined, {}, true);
    if (
      c.schema !== nativeWireSchema ||
      c.generation !== 'string' ||
      c.dispatcher !== nativeDispatcher
    )
      denied();
  };
  const inspect = async (a: NativePublicationRecord) => {
    const value = await pure('inspect', a);
    guards.effectCurrent();
    const html = await readFixed(pin.artifactRoot, a.artifactRelative, 8 * 1024 * 1024);
    guards.effectCurrent();
    if (
      value.artifactRelative !== a.artifactRelative ||
      value.artifactSha256 !== sha(html) ||
      canonical(value.publicMarker) !== canonical(publicMarker(wireBinding(a))) ||
      !/^[a-f0-9]{64}$/.test(value.publisherBindingSha256)
    )
      denied();
    return {
      artifactSha256: value.artifactSha256,
      publisherBindingSha256: value.publisherBindingSha256,
      artifactRelative: a.artifactRelative,
      completedOutputSha256: a.completedOutputSha256,
    };
  };
  const commandPlan = async (a: NativePublicationRecord, readonly = false) => {
    const b = wireBinding(a),
      p = releasePair(b);
    orderedPair(p, b);
    const v = await pure('commands', a, { pair: p }, readonly);
    if (
      typeof v.host !== 'string' ||
      !v.host ||
      /[\s@:]/.test(v.host) ||
      v.releaseId !== releaseId(b) ||
      v.publicUrl !== pin.publicOrigin + '/reports/' + a.artifactRelative ||
      canonical(v.orderedPair) !== canonical(orderedPair(p, b)) ||
      ['bootstrap', 'upload', 'transaction', 'receipt', 'verify'].some(
        (k) => typeof v[k] !== 'string' || !v[k] || Buffer.byteLength(v[k]) > 65536,
      )
    )
      denied();
    return v;
  };
  const immutable = async (a: NativePublicationRecord) => {
    guards.effectCurrent();
    await verify();
    guards.effectCurrent();
    const inspected = await inspect(a);
    if (
      inspected.artifactSha256 !== a.artifactSha256 ||
      inspected.publisherBindingSha256 !== a.publisherBindingSha256
    )
      denied();
    const root = pin.dispatchRoot;
    if ((await realpath(root)) !== root) denied();
    const info = await lstat(root);
    if (
      !info.isDirectory() ||
      info.mode & 0o077 ||
      (process.getuid && info.uid !== process.getuid())
    )
      denied();
    const dir = path.join(root, a.nativeActionId);
    await mkdir(dir, { mode: 0o700 });
    guards.effectCurrent();
    const html = await readFixed(pin.artifactRoot, a.artifactRelative, 8 * 1024 * 1024);
    guards.effectCurrent();
    if (sha(html) !== a.artifactSha256) denied();
    const sidecar = canonicalSidecar(wireBinding(a));
    const name = path.posix.basename(a.artifactRelative);
    await writeFile(path.join(dir, name), html, { flag: 'wx', mode: 0o400 });
    guards.effectCurrent();
    await writeFile(path.join(dir, name.slice(0, -5) + '.json'), sidecar, {
      flag: 'wx',
      mode: 0o400,
    });
    guards.effectCurrent();
    return dir;
  };
  const directories = new Map<string, string>(),
    completed = new Map<string, PublicationEffect[]>(),
    observed = new Map<string, NativePublicationReceipt>();
  const managedJobFor = async (
    a: NativePublicationRecord,
    entryId: 'canonical-producer' | 'generic-direct',
    nativeCurrent: () => void,
  ) => {
    const queueReceipts = new Map<string, unknown>();
    const baseCurrent = () => {
      nativeCurrent();
      coverageBindingCurrent();
    };
    let activeJobCurrent: (() => void) | undefined;
    const current = () => {
      baseCurrent();
      activeJobCurrent?.();
    };
    const safeQueue = async () => {
      current();
      if ((await realpath(pin.queueRoot)) !== pin.queueRoot) denied();
      const stat = await lstat(pin.queueRoot);
      current();
      if (
        !stat.isDirectory() ||
        stat.isSymbolicLink() ||
        stat.mode & 0o022 ||
        (process.getuid && stat.uid !== process.getuid())
      )
        denied();
    };
    const optional = async (root: string, name: string) => {
      try {
        const bytes = await readFixed(root, name, 65536);
        current();
        return bytes;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
        throw error;
      }
    };
    const atomic = async (root: string, name: string, value: unknown) => {
      current();
      const tmp = '.main-' + randomUUID() + '.tmp',
        bytes = Buffer.from(canonical(value) + '\n');
      const file = await open(
        path.join(root, tmp),
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        current();
        await file.writeFile(bytes);
        current();
        await file.sync();
        current();
      } finally {
        await file.close();
      }
      try {
        current();
        await rename(path.join(root, tmp), path.join(root, name));
        current();
      } finally {
        await unlink(path.join(root, tmp)).catch(() => {});
      }
      if (sha(await readFixed(root, name, 65536)) !== sha(bytes)) denied();
      current();
      return sha(bytes);
    };
    const scopeManifest = (m: any, artifactSha: string) => {
      const required = [
        'schema_version',
        'state',
        'queued_at',
        'artifact',
        'artifact_relative',
        'artifact_sha256',
        'public_url',
        'candidate_public_url',
        'source',
        'publisher_metadata',
        'publisher_metadata_sha256_at_queue',
        'publisher_binding_sha256',
        'template_producer',
        'template_family',
        'template_variant',
        'ui_contract',
        'dispatcher',
        'dispatcher_status',
      ];
      const diagnostic = ['last_failure', 'failure_count', 'consecutive_failures', 'failing_since'];
      if (
        !m ||
        required.some((k) => !Object.hasOwn(m, k)) ||
        Object.keys(m).some((k) => !required.includes(k) && !diagnostic.includes(k))
      )
        denied();
      for (const k of ['failure_count', 'consecutive_failures'])
        if (Object.hasOwn(m, k) && (!Number.isSafeInteger(m[k]) || m[k] < 0)) denied();

      if (
        !m ||
        m.schema_version !== 1 ||
        m.state !== 'queued' ||
        m.source !== 'bluebubbles-connect' ||
        m.artifact_relative !== a.artifactRelative ||
        m.artifact_sha256 !== artifactSha ||
        m.artifact !== path.join(pin.artifactRoot, a.artifactRelative) ||
        m.public_url !== null ||
        m.candidate_public_url !== pin.publicOrigin + '/reports/' + a.artifactRelative ||
        !/^[a-f0-9]{64}$/.test(m.publisher_binding_sha256) ||
        typeof m.queued_at !== 'string' ||
        !/(?:Z|[+-]\d\d:\d\d)$/.test(m.queued_at) ||
        !Number.isFinite(Date.parse(m.queued_at))
      )
        denied();
    };
    return coverage.prepareManagedJob(
      coverageRoot,
      {
        entryId,
        actionId: a.nativeActionId,
        actionRevision: a.actionRevision,
        bindingSha256: digest(wireBinding(a)),
        scopeSha256: digest([
          a.domainId,
          a.principalId,
          a.connectionId,
          a.generation,
          a.chatId,
          a.eventId,
          a.epoch,
          a.grantId,
          a.grantRevision,
        ]),
        releaseId: releaseId(wireBinding(a)),
      },
      baseCurrent,
      async (operation, candidate, jobCurrent) => {
        activeJobCurrent = jobCurrent;
        const guard = current;
        guard();
        if (operation === 'confirm-claim') {
          const op = typeof candidate.operationId === 'string' ? candidate.operationId : denied();
          const receipt =
            queueReceipts.get(op) ??
            (completed
              .get(a.nativeActionId)
              ?.some((e) => op === releaseId(wireBinding(a)) + ':' + e)
              ? { operationId: op, mainDispatched: true }
              : undefined);
          if (!receipt) denied();
          return receipt;
        }
        if (operation === 'confirm-session') {
          if (entryId === 'canonical-producer' && queueReceipts.size)
            return { mainQueueReceipts: [...queueReceipts.values()] };
          const own = observed.get(a.nativeActionId);
          if (entryId === 'generic-direct' && own) return { mainReceiptSha256: own.receiptSha256 };
          denied();
        }
        if (entryId !== 'canonical-producer') denied();
        await safeQueue();
        guard();
        if (operation === 'queue-write') {
          if (Object.keys(candidate).sort().join(',') !== 'expectedBeforeSha256,manifest') denied();
          const m = candidate.manifest as any;
          scopeManifest(m, m?.artifact_sha256);
          const html = await readFixed(pin.artifactRoot, a.artifactRelative, 8 * 1024 * 1024);
          guard();
          if (sha(html) !== m.artifact_sha256) denied();
          const metaRel = a.artifactRelative.slice(0, -5) + '.json',
            metaRaw = await readFixed(pin.artifactRoot, metaRel, 65536);
          guard();
          const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metaRaw));
          if (
            canonical(metadata.provenance) !== canonical(publicMarker(wireBinding(a))) ||
            m.publisher_metadata !== path.posix.basename(metaRel) ||
            sha(metaRaw) !== m.publisher_metadata_sha256_at_queue ||
            metadata.publisher_binding_sha256 !== m.publisher_binding_sha256
          )
            denied();
          const name = m.artifact_sha256 + '.json',
            old = await optional(pin.queueRoot, name);
          guard();
          if ((old ? sha(old) : null) !== candidate.expectedBeforeSha256) denied();
          if (old) {
            const before = JSON.parse(old.toString('utf8'));
            scopeManifest(before, m.artifact_sha256);
            for (const [k, v] of Object.entries(before)) {
              if (k === 'consecutive_failures') {
                if (!Number.isSafeInteger(m[k]) || m[k] < (v as number)) denied();
              } else if (k === 'failing_since') {
                if (!m[k] || Date.parse(m[k]) > Date.parse(v as string)) denied();
              } else if (canonical(m[k]) !== canonical(v)) denied();
            }
          }
          guard();
          const manifestSha256 = await atomic(pin.queueRoot, name, m);
          guard();
          const receipt = {
            jobOperation: 'queue-write',
            artifactSha256: m.artifact_sha256,
            manifestSha256,
            bindingSha256: digest(wireBinding(a)),
          };
          queueReceipts.set('queue:' + m.artifact_sha256, receipt);
          return receipt;
        }
        if (operation === 'queue-archive') {
          if (
            Object.keys(candidate).sort().join(',') !== 'expectedBeforeSha256,predecessorSha256' ||
            !/^[a-f0-9]{64}$/.test(candidate.predecessorSha256 as string) ||
            !queueReceipts.size
          )
            denied();
          const prior = candidate.predecessorSha256 as string,
            name = prior + '.json',
            raw = await optional(pin.queueRoot, name);
          guard();
          if (!raw || sha(raw) !== candidate.expectedBeforeSha256) denied();
          const before = JSON.parse(raw!.toString('utf8'));
          scopeManifest(before, prior);
          const replacement = [...queueReceipts.values()].find(
            (r: any) => r.jobOperation === 'queue-write',
          ) as any;
          if (!replacement || replacement.artifactSha256 === prior) denied();
          const successorRaw = await readFixed(
            pin.queueRoot,
            replacement.artifactSha256 + '.json',
            65536,
          );
          guard();
          if (sha(successorRaw) !== replacement.manifestSha256) denied();
          const successor = JSON.parse(successorRaw.toString('utf8'));
          scopeManifest(successor, replacement.artifactSha256);
          const failures = Math.max(before.failure_count ?? 0, before.consecutive_failures ?? 0);
          if (
            failures &&
            (!Number.isSafeInteger(successor.consecutive_failures) ||
              successor.consecutive_failures < failures)
          )
            denied();
          const since = before.failing_since ?? before.last_failure?.failed_at;
          if (
            since &&
            (!successor.failing_since ||
              !Number.isFinite(Date.parse(since)) ||
              Date.parse(successor.failing_since) > Date.parse(since))
          )
            denied();
          const archived = {
            ...before,
            state: 'superseded',
            superseded_at: new Date().toISOString(),
            superseded_by_artifact_sha256: replacement.artifactSha256,
          };
          for (const rel of ['archive', 'archive/generic-html']) {
            try {
              await mkdir(path.join(pin.queueRoot, rel), { mode: 0o700 });
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
            }
            const info = await lstat(path.join(pin.queueRoot, rel));
            guard();
            if (info.isSymbolicLink() || !info.isDirectory() || info.mode & 0o022) denied();
          }
          const stamp =
            new Date(before.queued_at)
              .toISOString()
              .slice(0, 19)
              .replaceAll('-', '')
              .replaceAll(':', '') + 'Z';
          const archiveName =
            path.posix.basename(a.artifactRelative, '.html') + '.' + prior + '.' + stamp + '.json';
          if (await optional(pin.queueRoot, 'archive/generic-html/' + archiveName)) denied();
          guard();
          const manifestSha256 = await atomic(pin.queueRoot, name, archived);
          guard();
          await rename(
            path.join(pin.queueRoot, name),
            path.join(pin.queueRoot, 'archive/generic-html', archiveName),
          );
          guard();
          if (
            sha(await readFixed(pin.queueRoot, 'archive/generic-html/' + archiveName, 65536)) !==
            manifestSha256
          )
            denied();
          guard();
          return {
            jobOperation: 'queue-archive',
            predecessorSha256: prior,
            manifestSha256,
            bindingSha256: digest(wireBinding(a)),
          };
        }
        denied();
      },
    );
  };
  const observe = async (a: NativePublicationRecord) => {
    const current = guards.readCurrent;
    current();
    const plan = await commandPlan(a, true);
    const r = await io.execute('/usr/bin/ssh', [plan.host, plan.receipt], current);
    current();
    let remote;
    try {
      remote = JSON.parse(r.stdout.toString('utf8'));
    } catch {
      denied();
    }
    const b = wireBinding(a),
      pair = releasePair(b),
      expected = {
        schema_version: 1,
        release_id: releaseId(b),
        status: 'verified-after-public-readback',
        pair,
      };
    if (canonical(remote) !== canonical(expected)) denied();
    const verified = await io.execute('/usr/bin/ssh', [plan.host, plan.verify], current);
    current();
    if (
      canonical(verified.stdout.toString('utf8').trim().split('\n')) !==
      canonical(orderedPair(pair, b).map(([, s]) => s))
    )
      denied();
    const bytes = await io.readback(plan.publicUrl + '?generic_release=' + releaseId(b), current);
    current();
    if (sha(bytes) !== a.artifactSha256) denied();
    const raw = {
      schema: nativeWireSchema,
      ...Object.fromEntries(
        [
          'nativeActionId',
          'actionRevision',
          'grantId',
          'grantRevision',
          'completedOutputSha256',
          'artifactSha256',
          'publisherBindingSha256',
          'artifactRelative',
        ].map((k) => [k, a[k as keyof NativePublicationRecord]]),
      ),
      dispatcher: nativeDispatcher,
      delivery_state: 'applied',
      remoteReleaseId: releaseId(b),
      verifiedSha256: a.artifactSha256,
      public_url_verified: true,
      observedAt: new Date().toISOString(),
    };
    const receipt = { ...raw, receiptSha256: digest(raw) } as NativePublicationReceipt;
    observed.set(a.nativeActionId, receipt);
    return {
      state: 'APPLIED_VERIFIED',
      binding: b,
      receipt,
      remoteReceipt: remote,
      finalPair: pair,
      publicReadbackSha256: a.artifactSha256,
    };
  };
  const session = async (
    a: NativePublicationRecord,
    control: NativePublicationControl | undefined,
    readonly = false,
  ) => {
    await verifyFiles();
    if (!readonly) await verify();
    const current = readonly ? guards.readCurrent : guards.effectCurrent;
    current();
    const managedJob = readonly ? undefined : await managedJobFor(a, 'generic-direct', current);
    const slug = path.posix.basename(a.artifactRelative, '.html');
    if (!/^imessage-[a-f0-9]{32}$/.test(slug) || !a.artifactSha256) denied();
    const launch =
      managedJob && pin.managedPublisher
        ? await pin.managedPublisher.controller.prepareOwnedChild(
            managedJob,
            pin.managedPublisher.source,
            {
              operation: 'generic',
              slug,
              artifactSha256: a.artifactSha256!,
              artifacts: pin.artifactRoot,
              queue: pin.queueRoot,
            },
          )
        : undefined;
    return new Promise<NativePublicationReceipt>((resolve, reject) => {
      let ended = false,
        wire = Buffer.alloc(0),
        output = Buffer.alloc(0),
        sequence = 0,
        awaiting = false;
      const challenges = new Set<string>();
      let chain = Promise.resolve();
      const child = launch
        ? launch()
        : spawn(
            pin.python.path,
            [
              '-I',
              '-c',
              readonly
                ? "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('scripts.publish_generic_html_direct',run_name='__main__')"
                : publicationManagedEntryPython,
              pin.root,
              ...(!readonly && managedJob
                ? [JSON.stringify(managedPublicationExpected(managedJob))]
                : []),
              readonly ? '--reconcile-native' : '--apply',
              '--slug',
              slug,
              '--artifact-sha256',
              a.artifactSha256!,
              '--native-control-read-fd',
              '3',
              '--native-control-write-fd',
              '4',
            ],
            {
              cwd: pin.root,
              env: managedJob
                ? {
                    ...env,
                    BRIDGE_CONSUMER_CONTROL_READ_FD: '5',
                    BRIDGE_CONSUMER_CONTROL_WRITE_FD: '6',
                  }
                : env,
              stdio: managedJob
                ? ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe']
                : ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'],
            },
          );
      let timer: ReturnType<typeof setTimeout>;
      const arm = () => {
        clearTimeout(timer);
        timer = setTimeout(() => finish(Error('TIMEOUT')), 10000);
      };
      const finish = (error?: unknown) => {
        if (ended) return;
        ended = true;
        clearTimeout(timer);
        child.stdio[3]?.destroy();
        child.stdio[4]?.destroy();
        if (error) {
          managedJob?.revoke();
          child.kill();
          reject(Error('NATIVE_ROOT_SESSION_UNKNOWN'));
          return;
        }
        try {
          const envelope = parseNativeFrame(
              new TextDecoder('utf-8', { fatal: true }).decode(output),
            ),
            candidate =
              envelope?.ok === true && envelope.consumer === nativeDispatcher
                ? envelope.result
                : undefined,
            receipt = observed.get(a.nativeActionId);
          if (
            !receipt ||
            !candidate ||
            candidate.delivery_state !== 'applied' ||
            candidate.public_url_verified !== true ||
            candidate.retry_allowed !== false ||
            candidate.artifact_sha256 !== a.artifactSha256 ||
            candidate.public_url !== null ||
            canonical(candidate.receipt) !== canonical(receipt) ||
            candidate.requires_main_receipt_validation !== true ||
            candidate.requires_main_return_authority !== true
          )
            denied();
          resolve(receipt!);
        } catch {
          reject(Error('NATIVE_ROOT_CANDIDATE_UNCONFIRMED'));
        }
      };
      arm();
      try {
        managedJob?.attach(child);
      } catch (error) {
        finish(error);
        return;
      }
      child.stderr?.on('data', () => {});
      child.stdout?.on('data', (b: Buffer) => {
        output = Buffer.concat([output, b]);
        if (output.length > 65536) finish(Error('LIMIT'));
      });
      child.stdio[3]?.on('error', () => finish(Error('PIPE')));
      child.stdio[4]?.on('error', () => finish(Error('PIPE')));
      (child.stdio[4] as NodeJS.ReadableStream).on('data', (b: Buffer) => {
        if (ended) return;
        wire = Buffer.concat([wire, b]);
        if (wire.length > 65536) {
          finish(Error('LIMIT'));
          return;
        }
        const nl = wire.indexOf(10);
        if (nl < 0) return;
        if (awaiting || nl !== wire.length - 1) {
          finish(Error('UNSOLICITED_FRAME'));
          return;
        }
        const frame = wire.subarray(0, nl);
        wire = Buffer.alloc(0);
        awaiting = true;
        chain = chain
          .then(async () => {
            const m = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(frame));
            if (
              canonical(Object.keys(m).sort()) !==
                canonical(['schema', 'sequence', 'challenge', 'operation', 'payload'].sort()) ||
              m.schema !== nativeWireSchema ||
              m.sequence !== ++sequence ||
              typeof m.challenge !== 'string' ||
              !/^[a-f0-9]{64}$/.test(m.challenge) ||
              challenges.has(m.challenge) ||
              !m.payload ||
              typeof m.payload !== 'object' ||
              Array.isArray(m.payload)
            )
              denied();
            challenges.add(m.challenge);
            current();
            let payload: unknown;
            const b = wireBinding(a),
              pair = releasePair(b),
              keys = Object.keys(m.payload).sort().join(',');
            const stageCheck = (s: any) => {
              if (
                !s ||
                Object.keys(s).sort().join(',') !==
                  'artifactRelative,artifactSha256,disclosure,publicMarker,publisherBindingSha256,target' ||
                s.target !== 'canonical-public-report' ||
                s.disclosure !== 'PUBLIC_RELEASE' ||
                s.artifactRelative !== a.artifactRelative ||
                s.artifactSha256 !== a.artifactSha256 ||
                s.publisherBindingSha256 !== a.publisherBindingSha256 ||
                canonical(s.publicMarker) !== canonical(publicMarker(b))
              )
                denied();
            };
            if (
              m.operation === 'stage_bind' &&
              !readonly &&
              control &&
              sequence === 1 &&
              keys === 'stage'
            ) {
              stageCheck(m.payload.stage);
              const fresh = await control.stageBind();
              if (canonical(wireBinding(fresh)) !== canonical(b)) denied();
              payload = { state: 'PREPARED_NO_REMOTE_EFFECT', binding: b };
            } else if (
              m.operation === 'before_effect' &&
              !readonly &&
              control &&
              keys === 'binding,effect,pair,releaseId'
            ) {
              if (
                canonical(m.payload.binding) !== canonical(b) ||
                m.payload.releaseId !== releaseId(b) ||
                m.payload.effect !== publicationEffects[sequence - 2]
              )
                denied();
              orderedPair(m.payload.pair, b);
              await control.beforeEffect(m.payload.effect);
              current();
              payload = {
                state: 'DISPATCHING_UNKNOWN',
                effect: m.payload.effect,
                bindingSha256: digest(b),
                dispatched: true,
              };
            } else if (
              m.operation === 'settle' &&
              !readonly &&
              control &&
              sequence === 5 &&
              keys === 'binding,dispatcher,pair'
            ) {
              if (
                canonical(m.payload.binding) !== canonical(b) ||
                m.payload.dispatcher !== nativeDispatcher
              )
                denied();
              orderedPair(m.payload.pair, b);
              const evidence = await observe(a);
              await control.settle(evidence.receipt);
              payload = evidence;
            } else if (
              m.operation === 'reconcile_readonly' &&
              readonly &&
              sequence === 1 &&
              keys === 'dispatcher,stage'
            ) {
              stageCheck(m.payload.stage);
              if (m.payload.dispatcher !== nativeDispatcher) denied();
              payload = await observe(a);
            } else denied();
            current();
            if (ended) denied();
            (child.stdio[3] as NodeJS.WritableStream).write(
              JSON.stringify({ ...m, payload }) + '\n',
            );
            awaiting = false;
            arm();
          })
          .catch(() => finish(Error('CONTROL_DENIED')));
      });
      child.on('error', () => finish(Error('START')));
      child.on('close', (code) => {
        void chain.then(async () => {
          if (code !== 0 || wire.length || awaiting) {
            managedJob?.revoke();
            finish(Error('EXIT'));
          } else {
            try {
              await managedJob?.finishProcess(true);
              finish();
            } catch (error) {
              finish(error);
            }
          }
        });
      });
    });
  };
  const runtime: NativePublisherRuntime = {
    identity: digest([
      pin.sourceIdentity,
      pin.root,
      pin.artifactRoot,
      pin.queueRoot,
      pin.dispatchRoot,
      pin.publicOrigin,
      files,
      pin.python,
    ]),
    publicOrigin: pin.publicOrigin,
    dispatcher: nativeDispatcher,
    verify,
    inspect,
    stage: async (a, text, control) => {
      await verify();
      guards.effectCurrent();
      await coverage.withAdmission(
        coverageRoot,
        a.nativeActionId + ':' + a.actionRevision,
        'stage',
        async (fence) => {
          const current = () => {
            guards.effectCurrent();
            coverageBindingCurrent();
            fence.assertCurrent();
          };
          current();
          const job = await managedJobFor(a, 'canonical-producer', current);
          await pure('stage', a, { text }, false, current, job);
          current();
          await control.stageBind();
          current();
        },
      );
    },
    apply: (a, control) => session(a, control),
    reconcile: (a) => session(a, undefined, true),
    dispatch: async (a, effect) => {
      guards.effectCurrent();
      await verify();
      guards.effectCurrent();
      const next = completed.get(a.nativeActionId) ?? [];
      if (
        effect !== publicationEffects[next.length] ||
        a.effects.length !== next.length + 1 ||
        a.effects.at(-1) !== effect
      )
        denied();
      const plan = await commandPlan(a);
      guards.effectCurrent();
      let dir = directories.get(a.nativeActionId);
      if (effect === 'remote-staging-prepare') {
        dir = await immutable(a);
        directories.set(a.nativeActionId, dir);
      }
      if (!dir) denied();
      const b = wireBinding(a),
        pair = orderedPair(releasePair(b), b);
      for (const [name, hash] of pair) {
        if (sha(await readFixed(dir!, name, 8 * 1024 * 1024)) !== hash) denied();
        guards.effectCurrent();
      }
      // No argv/host/path is taken from a root packet; only pinned canonical pure builders.
      await coverage.withAdmission(
        coverageRoot,
        a.nativeActionId + ':' + a.actionRevision,
        effect,
        async (fence) => {
          const current = () => {
            guards.effectCurrent();
            coverageBindingCurrent();
            fence.assertCurrent();
          };
          current();
          if (effect === 'remote-staging-prepare')
            await io.execute('/usr/bin/ssh', [plan.host, plan.bootstrap], current);
          else if (effect === 'remote-staging-upload')
            await io.execute(
              '/usr/bin/scp',
              [...pair.map(([name]) => path.join(dir!, name)), plan.host + ':' + plan.upload],
              current,
            );
          else await io.execute('/usr/bin/ssh', [plan.host, plan.transaction], current);
          current();
        },
      );
      guards.effectCurrent();
      next.push(effect);
      completed.set(a.nativeActionId, next);
      return { dispatched: true };
    },
  };
  return runtime;
}

/** Context comes from the Main-owned durable job, never from the child's hello. */
function managedPublicationExpected(job: ManagedPublicationJob) {
  const { schema: _schema, jobId: _jobId, expiresAt: _expiresAt, ...expected } = job.metadata;
  return expected;
}
