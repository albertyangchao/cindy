/** Main-owned canonical transport. Root child packets are candidates, never authority. */
import { spawn } from 'node:child_process';
import { open, lstat, realpath, mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { publicationPython } from './restrictedPublicationPython.js';
import {
  isConsumerGuardCoverageAuthority,
  type ConsumerGuardCoverageAuthority,
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
): Promise<Result> {
  current();
  return new Promise((resolve, reject) => {
    let ended = false;
    const chunks: Buffer[] = [];
    let size = 0;
    const child = spawn(executable, args, { ...options, stdio: ['pipe', 'pipe', 'pipe'] });
    const finish = (error?: unknown) => {
      if (ended) return;
      ended = true;
      clearTimeout(timer);
      child.stdin?.destroy();
      if (error) {
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
    child.stdin?.on('error', () => {});
    child.stderr?.on('data', () => {});
    child.stdout?.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) finish(Error('LIMIT'));
      else chunks.push(chunk);
    });
    child.on('error', finish);
    child.on('close', (code) => finish(code === 0 ? undefined : Error('EXIT')));
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
  ) => {
    const current = () => {
      (readonly ? guards.readCurrent : guards.effectCurrent)();
      coverageCurrent?.();
    };
    await verifyFiles();
    current();
    const result = await boundedProcess(
      pin.python.path,
      ['-I', '-c', publicationPython, pin.root],
      {
        operation,
        ...(a ? { binding: wireBinding(a), artifactRoot: pin.artifactRoot } : {}),
        ...extra,
      },
      { cwd: pin.root, env },
      current,
      10000,
      65536,
    );
    current();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout));
  };
  const verify = async () => {
    await verifyFiles();
    await pin.assertConsumerGuards();
    await coverage.readCurrent(coverageRoot, coverage.freshChallenge(coverageRoot));
    coverageBindingCurrent();
    guards.readCurrent();
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
    const slug = path.posix.basename(a.artifactRelative, '.html');
    if (!/^imessage-[a-f0-9]{32}$/.test(slug) || !a.artifactSha256) denied();
    return new Promise<NativePublicationReceipt>((resolve, reject) => {
      let ended = false,
        wire = Buffer.alloc(0),
        output = Buffer.alloc(0),
        sequence = 0,
        awaiting = false;
      const challenges = new Set<string>();
      let chain = Promise.resolve();
      const child = spawn(
        pin.python.path,
        [
          '-I',
          '-c',
          "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('scripts.publish_generic_html_direct',run_name='__main__')",
          pin.root,
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
        { cwd: pin.root, env, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'] },
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
        void chain.then(() => {
          if (code !== 0 || wire.length || awaiting) finish(Error('EXIT'));
          else finish();
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
          await pure('stage', a, { text }, false, current);
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
