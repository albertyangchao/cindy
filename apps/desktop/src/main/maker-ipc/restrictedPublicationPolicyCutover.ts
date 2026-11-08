/** Main-only generation cutover. Plans are immutable expectations, never facts.
 * No renderer/IPC entry, service launcher, business release or recovery replay.
 */
import { constants } from 'node:fs';
import { lstat, realpath, open, mkdir, rename } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { canonical, digest, parseNativeFrame } from './restrictedPublicationProtocol.js';
import { readPublicationHistoryReceipt, type createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import { ManagedPublicationController, readPreparedInstallReceipt } from './restrictedPublicationManagedController.js';
import { isOriginalPublicationRegistry, type OriginalPublicationRegistryProfile,
  type RestrictedPublicationOwnerRegistry } from './restrictedPublicationOwnerRegistry.js';
import { isOriginalPublicationSource, type PinnedPublicationResidentSource,
  type RestrictedPublicationResidentSource } from './restrictedPublicationResidentSource.js';
import type { FixedCoverageProfile, MainPublicationSourcePlan } from './restrictedPublicationCoverageDriver.js';

type Store = Pick<ReturnType<typeof createRestrictedPartnerStore>, 'consumerGuardReceiptIdentity' |
  'capturePublicationOwnerHistory' | 'assertPublicationOwnerHistoryCurrent' |
  'readConsumerGuardReceipt' | 'compareAndSwapConsumerGuardReceipt' |
  'unresolvedConsumerGuardAdmissions' | 'unknownNativePublicationEffects'>;
type Row = NonNullable<Awaited<ReturnType<Store['readConsumerGuardReceipt']>>>;
type Held = { source: RestrictedPublicationResidentSource; handle: object };
export interface MainPublicationGenerationPlan {
  generation: string;
  profile: FixedCoverageProfile;
  sourcePlan: Omit<MainPublicationSourcePlan, 'generations'>;
  /** A composite input is independently assembled from its registered origins.
   * These are source locations, not install or owner receipts. */
  additionalInstallations?: ReadonlyArray<{ runtimeDirectory: string; sourceRoot: string; releasesRoot: string }>;
}
const hash = (raw: Uint8Array | string) => createHash('sha256').update(raw).digest('hex');
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const opaque = (v: unknown): v is string => typeof v === 'string' && v.length > 0 &&
  Buffer.byteLength(v) <= 512 && !/[\u0000-\u001f\u007f-\u009f]/.test(v);
const relative = (value: string) => opaque(value) && !path.isAbsolute(value) && !value.includes('\\') &&
  value.split('/').every(x => x && x !== '.' && x !== '..');
function fail(code: string): never { throw Error('PUBLICATION_POLICY_CUTOVER_' + code); }
const stamp = (s: Awaited<ReturnType<typeof lstat>>) =>
  [s.dev, s.ino, s.mode, s.uid, s.gid, s.nlink, s.size, s.mtimeMs, s.ctimeMs].join(':');
async function directory(directoryPath: string) {
  if (!path.isAbsolute(directoryPath) || path.normalize(directoryPath) !== directoryPath ||
      await realpath(directoryPath) !== directoryPath) fail('PATH');
  for (let current = directoryPath;; current = path.dirname(current)) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink() ||
        ((info.mode & 0o022) && !((info.mode & 0o1000) && info.uid === 0))) fail('DIRECTORY');
    if (path.dirname(current) === current) break;
  }
}
async function bytes(file: string, expected: string, limit = 8 * 1024 * 1024) {
  if (!hex(expected) || !path.isAbsolute(file) || await realpath(file) !== file) fail('PIN');
  await directory(path.dirname(file));
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
      (before.mode & 0o022) || before.size > limit) fail('PIN');
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (stamp(await fd.stat()) !== stamp(before)) fail('PIN_CHANGED');
    const raw = await fd.readFile();
    if (raw.length !== before.size || hash(raw) !== expected || stamp(await fd.stat()) !== stamp(before) ||
        stamp(await lstat(file)) !== stamp(before) || await realpath(file) !== file) fail('PIN_CHANGED');
    return { raw, identity: stamp(before), mode: before.mode & 0o777 };
  } finally { await fd.close(); }
}
async function syncDirectory(directoryPath: string) {
  const fd = await open(directoryPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}
/** Pure approval identity. Original Main dispatch/runner approval callbacks
 * remain private; the complete target descriptors are part of the identity. */
export function publicationGenerationPlanIdentity(plan: MainPublicationGenerationPlan) {
  const ci = plan.sourcePlan.ci;
  const runners = plan.sourcePlan.ciRunners;
  return digest({ ...plan, sourcePlan: { ...plan.sourcePlan,
    ...(runners ? { ciRunners: runners.map(x => ({ instanceId: x.instanceId, effects: x.effects })) } : {}),
    ...(ci ? { ci: { instanceId: ci.instanceId, head: ci.head, workflowSha256: ci.workflowSha256 } } : {}) } });
}
export function clonePublicationGenerationPlan(plan: MainPublicationGenerationPlan): MainPublicationGenerationPlan {
  const ci = plan.sourcePlan.ci;
  const runners = plan.sourcePlan.ciRunners;
  const cloned = structuredClone({ ...plan, sourcePlan: { ...plan.sourcePlan,
    ...(runners ? { ciRunners: runners.map(x => ({ instanceId: x.instanceId, effects: x.effects })) } : {}),
    ...(ci ? { ci: { instanceId: ci.instanceId, head: ci.head, workflowSha256: ci.workflowSha256 } } : {}) } });
  return { ...cloned, sourcePlan: { ...cloned.sourcePlan,
    ...(runners ? { ciRunners: cloned.sourcePlan.ciRunners!.map((x, index) => ({ ...x,
      assertEffectApproved: runners[index].assertEffectApproved })) } : {}),
    ...(ci ? { ci: { ...ci } } : {}) } } as MainPublicationGenerationPlan;
}
export async function assertNoUncertainPublicationCutover(store: Store, plugin: string, account: string) {
  const handle = await store.capturePublicationOwnerHistory(plugin, account);
  const original = readPublicationHistoryReceipt(handle, store.consumerGuardReceiptIdentity, plugin, account);
  for (const row of original.rows) {
    const value = JSON.parse(row.payload) as Record<string, unknown>;
    if ((value.schema === 'publication-original-policy-cutover/v1' ||
         value.schema === 'publication-managed-prepared-install/v1') && value.state !== 'COMMITTED')
      fail('PRIOR_CUTOVER_UNKNOWN');
    if (value.schema === 'publication-original-owner-listener/v1' &&
        ['UNKNOWN', 'ROTATING_UNKNOWN', 'CUTOVER_HELD'].includes(String(value.state))) fail('PRIOR_CUTOVER_UNKNOWN');
  }
  await store.assertPublicationOwnerHistoryCurrent(handle, plugin, account);
}
async function definitionMatches(plan: MainPublicationGenerationPlan, root: string, sourceDigest: string) {
  const definition = plan.sourcePlan.worker.definition;
  if (!definition) fail('DEFINITION_REQUIRED');
  const raw = (await bytes(definition.profilePath, definition.profileSha256, 65535)).raw;
  const value = parseNativeFrame(new TextDecoder('utf-8', { fatal: true }).decode(raw)) as Record<string, any>;
  const wanted = plan.profile.instances.filter(x => x.origin === 'foreign-controller');
  if (value.schema !== 'publication-definition-profile/v1' || value.sourceRoot !== root || value.monitorRoot !== definition.monitorRoot ||
      value.sourceDigest !== sourceDigest || canonical(value.sourceFiles) !== canonical(plan.profile.source.files) ||
      canonical(value.python) !== canonical(plan.profile.source.python) ||
      !Array.isArray(value.instances) || value.instances.length !== wanted.length ||
      wanted.some(x => !value.instances.some((y: any) => y.instanceId === x.instanceId && y.entryId === x.entryId &&
        y.state === x.state && y.definitionDigest === plan.profile.registration.instances.find(z => z.instanceId === x.instanceId)?.entryDefinitionDigest)))
    fail('DEFINITION_PLAN_MISMATCH');
  for (const original of plan.sourcePlan.originalSources ?? []) for (const owner of original.owners) {
    if (owner.sourceScope === 'RESIDENT_ORIGINAL_ENTRY' && !value.instances.some((x: any) =>
      x.instanceId === owner.instanceId && x.definitionDigest === owner.definitionDigest)) fail('DEFINITION_OWNER_MISMATCH');
    if (owner.sourceScope === 'REGISTERED_NAMESPACE_OWNER' && !value.namespaces?.some((x: any) =>
      x.entryId === owner.ownerId && x.sourceRoot === original.root && x.sourceDigest === original.sourceDigest &&
      canonical(x.sourceFiles) === canonical(original.files))) fail('DEFINITION_OWNER_MISMATCH');
    if (owner.sourceScope === 'REGISTERED_RESIDENT_NONPUBLISHER' && !value.residentNonPublishers?.some((x: any) =>
      x.serviceLabel === owner.ownerId && x.definitionDigest === owner.definitionDigest &&
      value.residentNonPublisherSources?.some((y: any) => y.sourceProfileId === x.sourceProfileId &&
        y.sourceRoot === original.root && canonical(y.sourceFiles) === canonical(original.files)))) fail('DEFINITION_OWNER_MISMATCH');
    if (owner.sourceScope === 'REGISTERED_CI_PRODUCER' &&
        !plan.sourcePlan.ciRunners?.some(x => x.instanceId === owner.instanceId)) fail('DEFINITION_OWNER_MISMATCH');
  }
  return value as OriginalPublicationRegistryProfile;
}
type Prepared = { owner: object; controller: ManagedPublicationController; plan: MainPublicationGenerationPlan;
  managed: object; row: Row; key: string; store: Store; plugin: string; account: string;
  verifyOriginalPreparation: () => Promise<void>;
  verifyInstalledInputs: () => Promise<void>;
  expected: { root: string; sourceDigest: string; files: Record<string, string> }; consumed: boolean };
const prepared = new WeakMap<object, Prepared>();
const bootstrapDependencies = ['bridge_core/__init__.py', 'bridge_core/publication_owner_listener.py',
  'bridge_core/publication_resident_source.py'];
function bootstrapPaths(profile: PinnedPublicationResidentSource) {
  const paths = new Map<string, { originalRoot: string; relativePath: string; sha256: string }>();
  for (const owner of profile.owners) {
    const names = new Set([owner.originalEntryScript]);
    if (owner.originalEntryScript !== 'monitor/publication_nonpublisher_owner.py') {
      for (const name of bootstrapDependencies) names.add(name);
      if (owner.entryScript === 'bridge_core/publication_namespace_owner.py') for (const name of [
        owner.entryScript, 'bridge_core/publication_consumer_enrollment.py',
        'bridge_core/publication_consumer_guards.py', 'bridge_core/publish_queue_consumers.py',
        'bridge_core/html_contract.py', 'bridge_core/template_families.py']) names.add(name);
      if (owner.sourceScope === 'REGISTERED_CI_PRODUCER') for (const name of [
        'bridge_core/publication_ci_producer.py', 'macmini-jit-controller/publication_ci_owner.py']) names.add(name);
    }
    for (const relativePath of names) {
      const sha256 = relativePath === owner.originalEntryScript
        ? owner.originalBootstrapSha256 : profile.files[relativePath];
      if (!relative(relativePath) || !hex(sha256)) fail('BOOTSTRAP_SOURCE_REQUIRED');
      const target = path.join(owner.originalRoot, relativePath), old = paths.get(target);
      if (old && old.sha256 !== sha256) fail('BOOTSTRAP_CONFLICT');
      paths.set(target, { originalRoot: owner.originalRoot, relativePath, sha256 });
    }
  }
  return paths;
}
async function planBootstrapSwitch(oldProfiles: PinnedPublicationResidentSource[], nextProfiles: PinnedPublicationResidentSource[]) {
  const changes = new Map<string, { previous: string; next: string; source: string; previousIdentity?: string }>();
  for (const next of nextProfiles) {
    const old = oldProfiles.find(x => x.runtimeDirectory === next.runtimeDirectory);
    if (!old) fail('POLICY_REALM_MISSING');
    const before = bootstrapPaths(old);
    for (const [target, item] of bootstrapPaths(next)) {
      if ([...oldProfiles, ...nextProfiles].some(profile => target === profile.root ||
          target.startsWith(profile.root + path.sep))) fail('IMMUTABLE_BOOTSTRAP_COLLISION');
      const previous = before.get(target);
      if (!previous) fail('ORIGINAL_BOOTSTRAP_UNOBSERVED');
      const change = { previous: previous.sha256, next: item.sha256, source: path.join(next.root, item.relativePath) };
      const existing = changes.get(target);
      if (existing && (existing.previous !== change.previous || existing.next !== change.next)) fail('BOOTSTRAP_CONFLICT');
      if (!existing) changes.set(target, change);
    }
  }
  if (changes.size > 256) fail('BOOTSTRAP_LIMIT');
  for (const [target, change] of changes) {
    change.previousIdentity = (await bytes(target, change.previous)).identity;
    await bytes(change.source, change.next);
  }
  return changes;
}
/** Actual fixed bootstrap replacements, after every old listener has closed.
 * Shared Monitor/bootstrap paths are deduplicated; partial change stays UNKNOWN. */
async function switchBootstraps(changes: Awaited<ReturnType<typeof planBootstrapSwitch>>, check: () => Promise<void>) {
  const installed: Array<{ target: string; sha256: string; identity: string }> = [];
  for (const [target, change] of changes) {
    await check();
    const current = await bytes(target, change.previous);
    if (current.identity !== change.previousIdentity) fail('BOOTSTRAP_CHANGED');
    const next = await bytes(change.source, change.next);
    if (change.previous === change.next) {
      installed.push({ target, sha256: change.next, identity: current.identity });
      continue;
    }
    const temporary = target + '.publication-cutover-' + randomUUID();
    const fd = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, current.mode);
    try { await fd.writeFile(next.raw); await fd.sync(); } finally { await fd.close(); }
    await check();
    if ((await bytes(target, change.previous)).identity !== current.identity) fail('BOOTSTRAP_CHANGED');
    await rename(temporary, target);
    await syncDirectory(path.dirname(target));
    const verified = await bytes(target, change.next);
    installed.push({ target, sha256: change.next, identity: verified.identity });
    await check();
  }
  return installed;
}
async function verifyInstalledBootstraps(installed: Awaited<ReturnType<typeof switchBootstraps>>) {
  for (const pin of installed)
    if ((await bytes(pin.target, pin.sha256)).identity !== pin.identity) fail('BOOTSTRAP_CHANGED');
}
async function stageAdditional(plan: MainPublicationGenerationPlan, oldProfiles: PinnedPublicationResidentSource[],
  managedRoot: string, account: string, device: string, check: () => Promise<void>) {
  for (const next of plan.sourcePlan.originalSources ?? []) {
    if (next.root === managedRoot) continue;
    const old = oldProfiles.find(x => x.runtimeDirectory === next.runtimeDirectory);
    if (old && old.root === next.root && canonical(old.files) === canonical(next.files) &&
        canonical(old.python) === canonical(next.python)) continue;
    const origin = plan.additionalInstallations?.find(x => x.runtimeDirectory === next.runtimeDirectory);
    if (!origin || next.root !== path.join(origin.releasesRoot,
      digest([account, device, plan.generation, next.runtimeDirectory]))) fail('ORIGINAL_INSTALL_SOURCE_REQUIRED');
    await directory(origin.sourceRoot); await directory(origin.releasesRoot); await check();
    if (Object.keys(next.files).length < 1 || Object.keys(next.files).length > 256) fail('SOURCE_LIMIT');
    await mkdir(next.root, { mode: 0o700 });
    let total = 0;
    for (const [relativePath, expectedHash] of Object.entries(next.files)) {
      if (!relative(relativePath)) fail('SOURCE_PATH');
      const source = await bytes(path.join(origin.sourceRoot, relativePath), expectedHash);
      if ((total += source.raw.length) > 64 * 1024 * 1024) fail('SOURCE_LIMIT');
      await check();
      const target = path.join(next.root, relativePath);
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      const fd = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await fd.writeFile(source.raw); await fd.sync(); } finally { await fd.close(); }
      await bytes(target, expectedHash);
    }
    await syncDirectory(next.root); await check();
  }
}
export async function preparePublicationGenerationCutover(owner: object, store: Store, plugin: string,
  controller: ManagedPublicationController, registry: RestrictedPublicationOwnerRegistry, retirementReceipt: object,
  drainedHandle: object, held: Held[], plan: MainPublicationGenerationPlan, current: () => void) {
  if (!(controller instanceof ManagedPublicationController) || !isOriginalPublicationRegistry(registry) ||
      !opaque(plan.generation) || !/^[A-Za-z0-9_-]{1,100}$/.test(plan.sourcePlan.operationId) ||
      !held.length || held.some(x => !isOriginalPublicationSource(x.source))) fail('OWNER');
  const oldProfiles = held.map(x => x.source.retainedPolicyProfile(x.handle));
  const nextProfiles = plan.sourcePlan.originalSources;
  if (!nextProfiles || nextProfiles.length !== held.length ||
      new Set(nextProfiles.map(x => x.runtimeDirectory)).size !== nextProfiles.length ||
      nextProfiles.some(x => !oldProfiles.some(y => y.runtimeDirectory === x.runtimeDirectory))) fail('POLICY_REALMS');
  const drained = await controller.verifyLifecycleReceipt(drainedHandle);
  if (drained.phase !== 'DRAINED' || plan.generation === drained.binding.generation ||
      plan.sourcePlan.operationId === drained.operationId) fail('GENERATION');
  const account = drained.binding.accountId;
  const key = digest(['publication-original-policy-cutover/v1', drained.binding.deviceId,
    oldProfiles.map(x => x.runtimeDirectory).sort(), drained.binding.generation, plan.generation]);
  const journal = { schema: 'publication-original-policy-cutover/v1', scope: 'REGISTERED_POLICY_REALMS_ONLY',
    state: 'UNKNOWN', generation: plan.generation, operationId: plan.sourcePlan.operationId,
    originalDrain: digest(drained), planSha256: publicationGenerationPlanIdentity(plan) };
  let row: Row = { revision: 1, payload: canonical(journal) };
  if (!await store.compareAndSwapConsumerGuardReceipt(plugin, account, key, undefined, row.payload)) fail('CUTOVER_REPLAY');
  const history = await store.capturePublicationOwnerHistory(plugin, account);
  if (!await store.compareAndSwapConsumerGuardReceipt(plugin, account, key, row, row.payload, true, history)) fail('CUTOVER_CLAIM');
  row = { revision: row.revision + 1, payload: row.payload };
  const check = async () => {
    current();
    const value = await controller.verifyLifecycleReceipt(drainedHandle);
    if (canonical(value) !== canonical(drained) ||
        canonical(await store.readConsumerGuardReceipt(plugin, account, key)) !== canonical(row) ||
        await store.unresolvedConsumerGuardAdmissions(plugin, account) !== 0 ||
        await store.unknownNativePublicationEffects(plugin) !== 0) fail('CUTOVER_CHANGED');
    current();
  };
  await check();
  const managed = await controller.prepareInstall(plan.profile.source, plan.generation, plan.sourcePlan.operationId, drainedHandle);
  const installed = readPreparedInstallReceipt(managed, controller);
  if (plan.sourcePlan.worker.root !== installed.root ||
      canonical(plan.sourcePlan.worker.files) !== canonical(installed.files) ||
      canonical(plan.sourcePlan.worker.python) !== canonical(plan.profile.source.python)) fail('SOURCE_RELEASE_BINDING');
  await stageAdditional(plan, oldProfiles, installed.root, account, drained.binding.deviceId, check);
  const definition = await definitionMatches(plan, installed.root, installed.sourceDigest);
  await registry.validateCutoverDefinition(retirementReceipt, drainedHandle, definition);
  const bootstrapPlan = await planBootstrapSwitch(oldProfiles, [...nextProfiles]);
  let bootstraps: Awaited<ReturnType<typeof switchBootstraps>> = [];
  const nextPins = new Map<string, { sha256: string; identity: string; maximum: number }>();
  for (const next of nextProfiles) {
    for (const [name, expected] of Object.entries(next.files)) {
      const file = path.join(next.root, name), actual = await bytes(file, expected, 4 * 1024 * 1024);
      const old = nextPins.get(file);
      if (old && (old.sha256 !== expected || old.identity !== actual.identity)) fail('SOURCE_CHANGED');
      nextPins.set(file, { sha256: expected, identity: actual.identity, maximum: 4 * 1024 * 1024 });
    }
    const actual = await bytes(next.python.path, next.python.sha256, 128 * 1024 * 1024);
    const old = nextPins.get(next.python.path);
    if (old && (old.sha256 !== next.python.sha256 || old.identity !== actual.identity)) fail('SOURCE_CHANGED');
    nextPins.set(next.python.path, { sha256: next.python.sha256, identity: actual.identity, maximum: 128 * 1024 * 1024 });
  }
  const worker = plan.sourcePlan.worker, checker = worker.definition!;
  for (const [file, expected, maximum] of [
    [checker.profilePath, checker.profileSha256, 65535],
    [path.join(checker.monitorRoot, 'monitor/publication_definition_receipts.py'), checker.monitorSha256, 1048576],
    [worker.gh.path, worker.gh.sha256, 128 * 1024 * 1024],
  ] as const) {
    const actual = await bytes(file, expected, maximum), old = nextPins.get(file);
    if (old && (old.sha256 !== expected || old.identity !== actual.identity)) fail('SOURCE_CHANGED');
    nextPins.set(file, { sha256: expected, identity: actual.identity, maximum });
  }
  await directory(worker.gh.homeDirectory); await directory(worker.gh.configDirectory);
  for (const original of held) {
    await check(); await controller.verifyPreparedInstall(managed);
    const previous = original.source.retainedPolicyProfile(original.handle);
    const next = nextProfiles.find(x => x.runtimeDirectory === previous.runtimeDirectory)!;
    if (next.root === installed.root && (next.sourceDigest !== installed.sourceDigest ||
        canonical(next.files) !== canonical(installed.files))) fail('POLICY_INSTALL_BINDING');
    await original.source.rotatePreparedPolicy(original.handle, next, drainedHandle, registry, retirementReceipt);
  }
  const verifyInstalledInputs = async () => {
    for (const original of held) await original.source.verifyPreparedPolicyRecord(original.handle);
    await registry.verifyCompletedRetirementRecord(retirementReceipt);
    for (const [file, pin] of nextPins)
      if ((await bytes(file, pin.sha256, pin.maximum)).identity !== pin.identity) fail('SOURCE_CHANGED');
    await verifyInstalledBootstraps(bootstraps);
  };
  const verifyOriginalPreparation = async () => {
    for (const original of held)
      await original.source.verifyPreparedPolicy(original.handle, drainedHandle, registry, retirementReceipt);
    await verifyInstalledInputs();
    await controller.verifyPreparedInstall(managed);
  };
  const finalCheck = async () => {
    await check(); await verifyOriginalPreparation(); await check();
  };
  await finalCheck();
  bootstraps = await switchBootstraps(bootstrapPlan, finalCheck);
  await finalCheck();
  const done = canonical({ ...journal, state: 'PREPARED' });
  const finalHistory = await store.capturePublicationOwnerHistory(plugin, account);
  await finalCheck();
  if (!await store.compareAndSwapConsumerGuardReceipt(plugin, account, key, row, done, true, finalHistory)) fail('CUTOVER_CLAIM');
  row = { revision: row.revision + 1, payload: done };
  const handle = Object.freeze(Object.create(null)) as object;
  prepared.set(handle, { owner, controller, plan: clonePublicationGenerationPlan(plan), managed, row, key, store, plugin, account,
    verifyOriginalPreparation, verifyInstalledInputs,
    expected: { root: installed.root, sourceDigest: installed.sourceDigest, files: { ...installed.files } }, consumed: false });
  return handle;
}
export async function commitPublicationGenerationCutover(handle: object, owner: object,
  controller: ManagedPublicationController, generation: string, current: () => void = () => {}) {
  const value = prepared.get(handle);
  if (!value || value.owner !== owner || value.controller !== controller || value.consumed ||
      value.plan.generation !== generation) fail('PRIVATE_PREPARATION_REQUIRED');
  value.consumed = true;
  try {
  current();
  if (canonical(await value.store.readConsumerGuardReceipt(value.plugin, value.account, value.key)) !== canonical(value.row))
    fail('CUTOVER_CHANGED');
  const before = await value.store.capturePublicationOwnerHistory(value.plugin, value.account);
  await value.verifyOriginalPreparation(); current();
  const committing = canonical({ ...JSON.parse(value.row.payload), state: 'COMMITTING_UNKNOWN' });
  if (!await value.store.compareAndSwapConsumerGuardReceipt(value.plugin, value.account, value.key,
    value.row, committing, true, before)) fail('CUTOVER_CLAIM');
  value.row = { revision: value.row.revision + 1, payload: committing };
  current();
  const release = await controller.commitPreparedInstall(value.managed);
  current();
  if (release.generation !== generation || release.root !== value.expected.root ||
      release.sourceDigest !== value.expected.sourceDigest || canonical(release.files) !== canonical(value.expected.files))
    fail('INSTALLED_BINDING');
  const lifecycle = await controller.produceLifecycle('INSTALLED');
  const fact = await controller.verifyLifecycleReceipt(lifecycle);
  if (fact.phase !== 'INSTALLED' || fact.operationId !== value.plan.sourcePlan.operationId ||
      fact.binding.generation !== generation || fact.root !== release.root) fail('INSTALLED_BINDING');
  const history = await value.store.capturePublicationOwnerHistory(value.plugin, value.account);
  await value.verifyInstalledInputs(); current();
  await controller.verifyLifecycleReceipt(lifecycle);
  current();
  if (canonical(await value.store.readConsumerGuardReceipt(value.plugin, value.account, value.key)) !== canonical(value.row))
    fail('CUTOVER_CHANGED');
  const payload = canonical({ ...JSON.parse(value.row.payload), state: 'COMMITTED', originalInstalled: digest(fact) });
  if (!await value.store.compareAndSwapConsumerGuardReceipt(value.plugin, value.account, value.key,
    value.row, payload, true, history)) fail('CUTOVER_CLAIM');
  value.row = { revision: value.row.revision + 1, payload };
  await value.verifyInstalledInputs(); current();
  await controller.verifyLifecycleReceipt(lifecycle);
  return { release, plan: clonePublicationGenerationPlan(value.plan) };
  } catch (error) {
    // Close only this capability's exact durable row. Never adopt or overwrite
    // a competing owner, and never reconstruct a consumed preparation.
    try {
      await value.store.compareAndSwapConsumerGuardReceipt(value.plugin, value.account, value.key,
        value.row, canonical({ ...JSON.parse(value.row.payload), state: 'UNKNOWN' }));
    } catch { /* Original ambiguity and any newer winner remain durable. */ }
    throw error;
  }
}
