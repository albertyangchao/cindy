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
  | 'consumerGuardReceiptIdentity'
>;
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
  usedGenerations: string[];
  release: Release | null;
};
const locks = new WeakMap<object, Promise<unknown>>();
const launches = new WeakSet<object>();
export class ManagedPublicationController {
  private readonly boot = randomUUID();
  private readonly key = sha('publication-managed-lifecycle/v1');
  private closed = true;
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
  private async write(state: Lifecycle) {
    this.ownerCurrent();
    const old = await this.store.readConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
    );
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
      old,
      JSON.stringify(state),
    );
    this.ownerCurrent();
    if (!ok) deny('CAS');
  }
  private async state(): Promise<Lifecycle> {
    const row = await this.store.readConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
    );
    this.ownerCurrent();
    if (!row)
      return {
        schema: 'publication-managed-lifecycle/v1',
        accountScopeRef: this.accountScopeRef,
        deviceScopeRef: this.deviceScopeRef,
        boot: this.boot,
        state: 'QUIESCING',
        sequence: 0,
        usedGenerations: [],
        release: null,
      };
    let s: Lifecycle;
    try {
      s = JSON.parse(row.payload);
    } catch {
      deny('LEDGER');
    }
    if (
      s.schema !== 'publication-managed-lifecycle/v1' ||
      s.accountScopeRef !== this.accountScopeRef ||
      s.deviceScopeRef !== this.deviceScopeRef ||
      !opaque(s.boot) ||
      !['QUIESCING', 'INSTALLED', 'ACTIVE', 'REVOKED', 'UNKNOWN'].includes(s.state) ||
      !Number.isSafeInteger(s.sequence) ||
      s.sequence < 0 ||
      !Array.isArray(s.usedGenerations) ||
      s.usedGenerations.some((x) => !opaque(x))
    )
      deny('LEDGER');
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
    this.closed = true;
    this.epoch++;
    await this.exclusive(async () => {
      const s = await this.state();
      await this.write({ ...s, boot: this.boot, state: 'QUIESCING', sequence: s.sequence + 1 });
      for (const x of this.jobs.values()) x.job.revoke();
      await this.write({ ...s, boot: this.boot, state: 'REVOKED', sequence: s.sequence + 2 });
    });
  }
  async drain(timeoutMs = 10000): Promise<void> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 30000) deny('TIMEOUT');
    this.closed = true;
    ++this.epoch;
    await this.exclusive(async () => {
      const s = await this.state();
      await this.write({ ...s, state: 'QUIESCING', sequence: s.sequence + 1 });
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        Promise.all([...this.jobs.values()].map((x) => x.settled)),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(Error('PUBLICATION_MANAGED_DRAIN_UNKNOWN')), timeoutMs);
        }),
      ]);
      if (
        (await this.store.unresolvedConsumerGuardAdmissions(this.plugin, this.accountScopeRef)) !==
        0
      )
        deny('DRAIN_UNKNOWN');
      await this.exclusive(async () => {
        const s = await this.state();
        await this.write({ ...s, state: 'REVOKED', sequence: s.sequence + 1 });
      });
    } catch (error) {
      this.closed = true;
      await this.exclusive(async () => {
        const s = await this.state();
        await this.write({ ...s, state: 'UNKNOWN', sequence: s.sequence + 1 });
      });
      throw error;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  /** Copy a pinned import closure to an immutable generation directory; never mutate old release.
   * A failure keeps the partial directory and UNKNOWN receipt, not an apparently complete install.
   */
  async install(source: PublisherReleaseSource, generation: string): Promise<Release> {
    source = structuredClone(source);
    this.closed = true;
    const epoch = ++this.epoch;
    return this.exclusive(async () => {
      const s = await this.state();
      if (
        !opaque(generation) ||
        s.usedGenerations.includes(generation) ||
        s.usedGenerations.length >= 1024
      )
        deny('GENERATION');
      await this.write({
        ...s,
        boot: this.boot,
        state: 'QUIESCING',
        sequence: s.sequence + 1,
        usedGenerations: [...s.usedGenerations, generation],
      });
      try {
        if (
          this.jobs.size ||
          (await this.store.unresolvedConsumerGuardAdmissions(
            this.plugin,
            this.accountScopeRef,
          )) !== 0
        )
          deny('DRAIN_UNKNOWN');
        const files = { ...source.files };
        if (
          !Object.keys(files).length ||
          Object.keys(files).length > 512 ||
          !files['bridge_core/publication_consumer_controller.py'] ||
          !files['scripts/publish_generic_html_direct.py']
        )
          deny('SOURCE');
        await this.directory(source.sourceRoot);
        await this.directory(source.releasesRoot);
        const pythonRoot = path.dirname(source.python.path);
        await this.directory(pythonRoot);
        await this.bytes(pythonRoot, path.basename(source.python.path), source.python.sha256);
        const target = path.join(
          source.releasesRoot,
          sha([this.accountScopeRef, this.deviceScopeRef, generation]),
        );
        await mkdir(target, { mode: 0o700 });
        let totalBytes = 0;
        for (const [relative, expected] of Object.entries(files)) {
          const data = await this.bytes(source.sourceRoot, relative, expected);
          totalBytes += data.byteLength;
          if (totalBytes > 64 * 1024 * 1024) deny('SOURCE_BUDGET');
          this.ownerCurrent();
          if (this.epoch !== epoch) deny('REVOKED');
          const destination = path.join(target, relative);
          await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
          const temp = destination + '.install-' + randomUUID();
          const fd = await open(temp, 'wx', 0o600);
          try {
            await fd.writeFile(data);
            await fd.sync();
          } finally {
            await fd.close();
          }
          this.ownerCurrent();
          if (this.epoch !== epoch) {
            await unlink(temp);
            deny('REVOKED');
          }
          await rename(temp, destination);
          await this.bytes(target, relative, expected);
        }
        const release = { generation, root: target, sourceDigest: sha(files), files };
        if (this.epoch !== epoch) deny('REVOKED');
        await this.write({ ...(await this.state()), boot: this.boot, state: 'INSTALLED', release });
        this.release = release;
        return structuredClone(release);
      } catch (error) {
        await this.write({ ...(await this.state()), state: 'UNKNOWN' });
        throw error;
      }
    });
  }
  /** Activate ONLY this owned installed entry tree. This is not global coverage or a READY issuer. */
  async switchEntry(generation: string): Promise<void> {
    const epoch = this.epoch;
    await this.exclusive(async () => {
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
      await this.write({ ...s, state: 'ACTIVE', sequence: s.sequence + 1 });
      if (epoch !== this.epoch) deny('REVOKED');
      this.release = s.release;
      this.closed = false;
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
        this.jobs.delete(job.metadata.jobId);
      });
      // Keep rejected launch completion observed; drain() and account receipts preserve UNKNOWN.
      void settled.catch(() => {
        this.closed = true;
      });
      this.jobs.set(job.metadata.jobId, { child, job, settled });
      return child;
    };
  }
  async verifyCurrent(root: string): Promise<void> {
    try {
      this.assertCurrent(root);
      const s = await this.state();
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
      this.closed = true;
      ++this.epoch;
      throw error;
    }
  }
  assertCurrent(root: string): void {
    this.ownerCurrent();
    if (this.closed || !this.release || this.release.root !== root) deny('REVOKED');
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
