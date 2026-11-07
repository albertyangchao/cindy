import path from 'node:path';
import { digest as canonicalDigest } from './restrictedPublicationProtocol.js';
import type { RegisteredPublicationRoot } from './restrictedPublicationCaller.js';
import type { ConsumerGuardCoverageAuthority } from './restrictedPublicationConsumerGuardAuthority.js';
/** Main-private executable adapter. Profiles are expected definitions, never evidence.
 * Unknown foreign controller/namespace receipts remain unsupported, not absent/zero.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import {
  ManagedPublicationController,
  readManagedEnrollmentReceipt,
  type PublisherReleaseSource,
} from './restrictedPublicationManagedController.js';
import {
  coverageEntries,
  adjacentCoverageEntries,
  type CoverageRegistration,
  type ControlledCoverageDriver,
  type ControlledCoverageReport,
} from './restrictedPublicationConsumerGuardAuthority.js';
const sha = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
const validHash = (x: unknown): x is string => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const opaque = (x: unknown): x is string =>
  typeof x === 'string' &&
  x.length > 0 &&
  Buffer.byteLength(x) <= 512 &&
  !/[\u0000-\u001f\u007f]/.test(x);
function fail(code: string): never {
  throw Error('PUBLICATION_DRIVER_' + code);
}
const coreEntryFiles: Record<string, string[]> = {
  'canonical-producer': ['bridge_core/publish_html.py', 'bridge_core/report_publish_queue.py'],
  'generic-direct': ['scripts/publish_generic_html_direct.py'],
  'worksheet-ci': ['scripts/publish_worksheet_html.py'],
  'worksheet-direct': ['scripts/publish_worksheet_html_direct.py'],
  'tracker-direct': ['scripts/publish_tracker_html_direct.py'],
  'shared-transaction': ['scripts/publish_worksheet_html.py'],
  'native-main-dispatch': [],
};
const commonFiles = [
  'bridge_core/publication_consumer_guards.py',
  'bridge_core/publication_consumer_controller.py',
  'bridge_core/publication_consumer_enrollment.py',
  'bridge_core/native_html_release.py',
];
export function coverageEntryDefinition(
  entryId: string,
  files: Readonly<Record<string, string>>,
): string {
  if (!Object.hasOwn(coreEntryFiles, entryId)) fail('ENTRY');
  const expected: Record<string, string> = {};
  for (const p of [...commonFiles, ...coreEntryFiles[entryId]]) {
    if (!validHash(files[p])) fail('ENTRY_SOURCE');
    expected[p] = files[p];
  }
  return canonicalDigest({ entryId, files: expected });
}
type Store = Pick<
  ReturnType<typeof createRestrictedPartnerStore>,
  | 'consumerGuardReceiptIdentity'
  | 'readConsumerGuardReceipt'
  | 'compareAndSwapConsumerGuardReceipt'
  | 'unresolvedConsumerGuardAdmissions'
  | 'unknownNativePublicationEffects'
>;
export interface FixedCoverageProfile {
  source: PublisherReleaseSource;
  publisher: {
    artifactRoot: string;
    queueRoot: string;
    dispatchRoot: string;
    publicOrigin: string;
  };
  registration: CoverageRegistration;
  instances: ReadonlyArray<{
    instanceId: string;
    entryId: (typeof coverageEntries)[number];
    origin: 'owned-release' | 'foreign-controller';
    state: 'GUARDED' | 'NATIVE_NAMESPACE_DENIED' | 'RETIRED_FENCED';
  }>;
  /** Real original-owner source adapters must supply opaque receipts, not JSON reports.
   * No such foreign producer is registered by this module. */
  foreignSources?: ReadonlyArray<object>;
  namespaceOwnership: Readonly<
    Record<(typeof adjacentCoverageEntries)[number], 'owned-launcher' | 'foreign-controller'>
  >;
}
type DriverState = {
  schema: 'publication-coverage-driver/v1';
  boot: string;
  account: string;
  profile: string;
  releaseSequence: number;
  lifecycleSequence: number;
  usedGenerations: string[];
  lastVerified: ControlledCoverageReport | null;
  state: 'QUIESCING' | 'READY' | 'UNKNOWN';
};
const drivers = new WeakSet<object>();
export function isManagedCoverageDriver(x: unknown): x is ManagedCoverageDriver {
  return !!x && typeof x === 'object' && drivers.has(x);
}
export class ManagedCoverageDriver implements ControlledCoverageDriver {
  readonly issuerId = randomUUID();
  readonly registration: CoverageRegistration;
  private readonly boot = randomUUID();
  private readonly profile: FixedCoverageProfile;
  private readonly profileHash: string;
  private readonly key = sha('publication-coverage-driver/v1');
  private closed = true;
  private fence?: string;
  private leaseUntil = 0;
  private epoch = 0;
  private lastClock = 0;
  private accepted?: ControlledCoverageReport;
  constructor(
    private readonly store: Store,
    private readonly plugin: string,
    readonly accountScopeRef: string,
    readonly controller: ManagedPublicationController,
    profile: FixedCoverageProfile,
    private readonly ownerCurrent: () => void,
    private readonly now: () => number = Date.now,
  ) {
    if (
      !validHash(accountScopeRef) ||
      controller.accountScopeRef !== accountScopeRef ||
      !opaque(plugin) ||
      !(controller instanceof ManagedPublicationController)
    )
      fail('SCOPE');
    this.profile = structuredClone(profile);
    this.registration = structuredClone(this.profile.registration);
    this.profileHash = sha(this.profile);
    const r = this.registration;
    if (
      !validHash(r.rootIdentity) ||
      !validHash(r.rootDefinitionDigest) ||
      !validHash(r.deviceScopeRef) ||
      !validHash(r.inventoryDigest) ||
      !Array.isArray(r.instances) ||
      !Array.isArray(profile.instances) ||
      r.instances.length !== profile.instances.length ||
      r.instances.length < 7 ||
      r.instances.length > 64
    )
      fail('PROFILE');
    const ids = r.instances.map((x) => x.instanceId);
    if (new Set(ids).size !== ids.length || sha([...ids].sort()) !== r.registrationSetDigest)
      fail('MEMBERSHIP');
    for (const x of r.instances) {
      const p = profile.instances.filter((v) => v.instanceId === x.instanceId);
      if (
        !opaque(x.instanceId) ||
        !validHash(x.entryDefinitionDigest) ||
        !coverageEntries.includes(x.entryId) ||
        p.length !== 1 ||
        p[0].entryId !== x.entryId
      )
        fail('PROFILE');
    }
    if (coverageEntries.some((id) => !r.instances.some((x) => x.entryId === id)))
      fail('MEMBERSHIP');
    for (const x of this.profile.instances) {
      if (
        !['owned-release', 'foreign-controller'].includes(x.origin) ||
        !['GUARDED', 'NATIVE_NAMESPACE_DENIED', 'RETIRED_FENCED'].includes(x.state)
      )
        fail('PROFILE');
      if (
        [
          'canonical-producer',
          'generic-direct',
          'shared-transaction',
          'native-main-dispatch',
        ].includes(x.entryId) &&
        x.state !== 'GUARDED'
      )
        fail('REQUIRED_GUARD');
      if (x.origin === 'owned-release' && x.state === 'RETIRED_FENCED')
        fail('RETIREMENT_SOURCE_REQUIRED');
      if (
        x.origin === 'owned-release' &&
        this.registration.instances.find((i) => i.instanceId === x.instanceId)!
          .entryDefinitionDigest !== coverageEntryDefinition(x.entryId, this.profile.source.files)
      )
        fail('ENTRY_DEFINITION');
    }
    drivers.add(this);
  }
  private clock() {
    const t = this.now();
    if (!Number.isSafeInteger(t) || t < this.lastClock) {
      this.close();
      fail('CLOCK');
    }
    this.lastClock = t;
    return t;
  }
  private close() {
    this.closed = true;
    this.epoch++;
    this.leaseUntil = 0;
  }
  assertCurrent(fenceRef?: string) {
    this.ownerCurrent();
    if (sha(this.profile) !== this.profileHash) {
      this.close();
      fail('PROFILE_CHANGED');
    }
    const t = this.clock();
    // Authority calls current() during quiesce/install, before a business lease exists.
    // A supplied effect fence always requires a completed current report.
    if (fenceRef !== undefined && (this.closed || fenceRef !== this.fence || t >= this.leaseUntil))
      fail('LEASE_CLOSED');
    if (!this.closed && this.accepted)
      this.controller.assertCurrent(this.accepted.members.length ? this.activeRoot! : '');
  }
  private activeRoot?: string;
  private async read() {
    const row = await this.store.readConsumerGuardReceipt(
      this.plugin,
      this.accountScopeRef,
      this.key,
    );
    this.ownerCurrent();
    if (!row)
      return {
        row,
        value: {
          schema: 'publication-coverage-driver/v1',
          boot: this.boot,
          account: this.accountScopeRef,
          profile: this.profileHash,
          releaseSequence: 0,
          lifecycleSequence: 0,
          usedGenerations: [],
          lastVerified: null,
          state: 'QUIESCING',
        } as DriverState,
      };
    let v: DriverState;
    try {
      v = JSON.parse(row.payload);
    } catch {
      fail('LEDGER');
    }
    if (
      v!.schema !== 'publication-coverage-driver/v1' ||
      v!.account !== this.accountScopeRef ||
      v!.profile !== this.profileHash ||
      !Number.isSafeInteger(v!.releaseSequence) ||
      !Number.isSafeInteger(v!.lifecycleSequence) ||
      v!.releaseSequence < 0 ||
      v!.lifecycleSequence < 0 ||
      !Array.isArray(v!.usedGenerations)
    )
      fail('LEDGER');
    return { row, value: v! };
  }
  private async save(old: Awaited<ReturnType<ManagedCoverageDriver['read']>>, value: DriverState) {
    if (
      !(await this.store.compareAndSwapConsumerGuardReceipt(
        this.plugin,
        this.accountScopeRef,
        this.key,
        old.row,
        JSON.stringify(value),
      ))
    ) {
      this.close();
      fail('CAS');
    }
    this.ownerCurrent();
  }
  async quiesce() {
    this.close();
    await this.controller.revoke();
    await this.controller.drain();
    const observed = await this.controller.coverageSourceState();
    if (observed.ownedJobs !== 0 || observed.unresolved !== 0) fail('UNRESOLVED');
    if ((await this.store.unknownNativePublicationEffects(this.plugin)) !== 0)
      fail('NATIVE_EFFECT_UNKNOWN');
  }
  async switchRelease(
    generation: string,
    previousSequence: number,
  ): Promise<ControlledCoverageReport> {
    this.close();
    const epoch = this.epoch;
    this.ownerCurrent();
    const old = await this.read();
    if (
      !opaque(generation) ||
      old.value.usedGenerations.includes(generation) ||
      old.value.usedGenerations.length >= 1024
    )
      fail('GENERATION');
    if (old.value.lifecycleSequence !== previousSequence) fail('SEQUENCE_GAP');
    if ((await this.store.unknownNativePublicationEffects(this.plugin)) !== 0)
      fail('NATIVE_EFFECT_UNKNOWN');
    const pending: DriverState = {
      ...old.value,
      boot: this.boot,
      state: 'QUIESCING',
      usedGenerations: [...old.value.usedGenerations, generation],
    };
    await this.save(old, pending);
    try {
      const release = await this.controller.install(this.profile.source, generation);
      const loaded = new Map<string, object>();
      for (const x of this.profile.instances) {
        if (x.origin !== 'owned-release') fail('FOREIGN_SOURCE_UNSUPPORTED');
        if (x.entryId === 'native-main-dispatch') continue;
        // Retired/denied roles execute only the fixed no-business guard probe, never their business main.
        loaded.set(
          x.instanceId,
          await this.controller.probeEnrollment(this.profile.source, x.entryId),
        );
      }
      if (epoch !== this.epoch) fail('REVOKED');
      await this.controller.switchEntry(generation);
      this.activeRoot = release.root;
      if (
        !this.profile.publisher ||
        ![
          this.profile.publisher.artifactRoot,
          this.profile.publisher.queueRoot,
          this.profile.publisher.dispatchRoot,
        ].every((x) => path.isAbsolute(x))
      )
        fail('PUBLISHER_PROFILE');
      this.registration.rootIdentity = sha([
        this.accountScopeRef,
        this.registration.deviceScopeRef,
        generation,
        release.root,
        release.sourceDigest,
      ]);
      this.registration.rootDefinitionDigest = canonicalDigest([
        sha(this.profile.source.files),
        release.root,
        this.profile.publisher.artifactRoot,
        this.profile.publisher.queueRoot,
        this.profile.publisher.dispatchRoot,
        this.profile.publisher.publicOrigin,
        this.profile.source.files,
        this.profile.source.python,
      ]);
      const state = await this.controller.coverageSourceState();
      if (state.unresolved !== 0 || state.ownedJobs !== 0) fail('UNRESOLVED');
      const nativeUnknown = await this.store.unknownNativePublicationEffects(this.plugin);
      if (nativeUnknown !== 0) fail('NATIVE_EFFECT_UNKNOWN');
      const members = this.profile.instances.map((x) => {
        if (x.entryId === 'native-main-dispatch') {
          this.controller.assertCurrent(release.root);
          return {
            instanceId: x.instanceId,
            entryId: x.entryId,
            launchAuthorityId: this.issuerId,
            admissionReceiptId: sha([
              this.boot,
              release.root,
              state.boot,
              state.epoch,
              'main-current-kernel',
            ]),
            releaseGeneration: generation,
            guardSourceIdentity: this.registration.rootIdentity,
            entryDefinitionDigest: this.registration.instances.find(
              (i) => i.instanceId === x.instanceId,
            )!.entryDefinitionDigest,
            state: 'GUARDED' as const,
            effectFenceRevision: state.epoch + 1,
            dispositionReceiptId: null,
          };
        }
        const observation = readManagedEnrollmentReceipt(
          loaded.get(x.instanceId)!,
          this.controller,
        );
        if (
          observation.generation !== generation ||
          observation.accountScopeRef !== this.accountScopeRef ||
          observation.deviceScopeRef !== this.registration.deviceScopeRef ||
          observation.entryId !== x.entryId ||
          observation.inventoryDigest !== this.registration.inventoryDigest ||
          canonicalDigest({ entryId: x.entryId, files: observation.files }) !==
            this.registration.instances.find((i) => i.instanceId === x.instanceId)!
              .entryDefinitionDigest
        )
          fail('LOADED_BINDING');
        return {
          instanceId: x.instanceId,
          entryId: x.entryId,
          launchAuthorityId: this.issuerId,
          admissionReceiptId: sha(observation),
          releaseGeneration: generation,
          guardSourceIdentity: this.registration.rootIdentity,
          entryDefinitionDigest: this.registration.instances.find(
            (i) => i.instanceId === x.instanceId,
          )!.entryDefinitionDigest,
          state: x.state,
          effectFenceRevision: state.epoch + 1,
          dispositionReceiptId: x.state === 'GUARDED' ? null : sha(observation),
        };
      });
      // Source presence/probe does not prove remote/old namespace fences. No JSON provider fallback.
      const namespaceReceipt = await this.controller.probeEnrollment(
        this.profile.source,
        'owned-namespace-source',
      );
      const namespaceObservation = readManagedEnrollmentReceipt(namespaceReceipt, this.controller);
      if (namespaceObservation.generation !== generation) fail('NAMESPACE_BINDING');
      const exclusions: ControlledCoverageReport['exclusions'] = [];
      if (
        !this.profile.namespaceOwnership ||
        Object.keys(this.profile.namespaceOwnership).sort().join(',') !==
          [...adjacentCoverageEntries].sort().join(',')
      )
        fail('NAMESPACE_SOURCE_UNKNOWN');
      for (const entryId of adjacentCoverageEntries) {
        // This receipt covers ONLY the actual owned launcher. A real foreign producer
        // is deliberately not replaced by source hashes or self-supplied JSON.
        if (this.profile.namespaceOwnership[entryId] !== 'owned-launcher')
          fail('FOREIGN_NAMESPACE_SOURCE_UNSUPPORTED');
        const observation = readManagedEnrollmentReceipt(
          await this.controller.namespaceFence(this.profile.source, entryId),
          this.controller,
        );
        if (observation.entryId !== 'namespace:' + entryId || observation.generation !== generation)
          fail('NAMESPACE_BINDING');
        exclusions.push({
          entryId,
          namespace: 'native-publication',
          fenceReceiptId: sha(observation),
          definitionDigest: sha(observation.files),
          fenceRevision: state.epoch + 1,
        });
      }
      const report: ControlledCoverageReport = {
        releaseGeneration: generation,
        releaseSequence: old.value.releaseSequence + 1,
        lifecycleSequence: old.value.lifecycleSequence + 1,
        fenceRef: sha([this.boot, generation, state.epoch]),
        enrollmentReceiptId: sha(members),
        members,
        oldGenerationAdmissions: {
          unresolved: state.unresolved,
          fenceReceiptId: sha([this.boot, state.epoch, 'drained']),
        },
        unknownNativeEffects: nativeUnknown,
        exclusions,
      };
      if (epoch !== this.epoch) fail('REVOKED');
      const current = await this.read();
      await this.save(current, {
        ...pending,
        state: 'READY',
        releaseSequence: report.releaseSequence,
        lifecycleSequence: report.lifecycleSequence,
        lastVerified: report,
      });
      this.accepted = structuredClone(report);
      this.fence = report.fenceRef;
      this.closed = false;
      this.leaseUntil = this.clock() + 30000;
      return structuredClone(report);
    } catch (error) {
      this.close();
      const current = await this.read();
      await this.save(current, { ...current.value, state: 'UNKNOWN' });
      throw error;
    }
  }
  async refresh(): Promise<void> {
    this.requireReady();
    const epoch = this.epoch;
    await this.controller.verifyCurrent(this.activeRoot!);
    const persisted = await this.read();
    if (
      epoch !== this.epoch ||
      persisted.value.state !== 'READY' ||
      sha(persisted.value.lastVerified) !== sha(this.accepted)
    ) {
      this.close();
      fail('FACTS_CHANGED');
    }
    // Release drain/UNKNOWN counts are measured before switching generations.
    // An admitted current operation deliberately persists UNKNOWN before remote IO;
    // treating that as an unrelated old-generation claim here would self-revoke it.
    // Its original Main action/job authority still guards every effect and no-resubmit.
    if (epoch !== this.epoch) {
      this.close();
      fail('REVOKED');
    }
    this.requireReady();
    this.leaseUntil = this.clock() + 30000;
  }
  publicationRoot(authority: ConsumerGuardCoverageAuthority): RegisteredPublicationRoot {
    this.requireReady();
    if (!this.activeRoot) fail('SOURCE_UNSUPPORTED');
    return {
      root: this.activeRoot,
      ...this.profile.publisher,
      sourceIdentity: sha(this.profile.source.files),
      files: { ...this.profile.source.files },
      python: { ...this.profile.source.python },
      consumerCoverage: authority,
      consumerRootIdentity: this.registration.rootIdentity,
      managedPublisher: {
        controller: this.controller,
        source: structuredClone(this.profile.source),
      },
      assertConsumerGuards: async () => {
        await this.refresh();
      },
    };
  }
  matchesAccountDatabase(client: object): boolean {
    return client === this.store.consumerGuardReceiptIdentity;
  }
  requireReady() {
    if (!this.accepted || !this.fence) fail('SOURCE_UNSUPPORTED');
    this.assertCurrent(this.fence);
  }
  async status() {
    const s = await this.read();
    return {
      ...structuredClone(s.value),
      leaseCurrent: !this.closed && this.clock() < this.leaseUntil,
    };
  }
}
