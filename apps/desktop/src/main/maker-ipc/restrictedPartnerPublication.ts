/** Main-owned PUBLIC_RELEASE actions over the existing account receipt table. Not a publisher. */
import { createHash, randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { pluginTaskRequests } from '../localDb/schema.js';
import type { DbClient } from '../localDb/client/DbClient.js';
import type {
  RestrictedPartnerGrant,
  RestrictedPartnerClaim,
} from './restrictedPartnerExecution.js';
import {
  publicMarker,
  wireBinding,
  publicationEffects,
  releaseId,
  nativeWireSchema,
  nativeDispatcher,
} from './restrictedPublicationProtocol.js';
import { grantResourceFingerprint } from './restrictedPartnerRequirements.js';
export const publicationCanonical = (x: unknown): string =>
  JSON.stringify(x, (_k, v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, v[k]]),
        )
      : v,
  );
export const publicationSha = (x: unknown) =>
  createHash('sha256').update(publicationCanonical(x)).digest('hex');
const shaText = (x: string) => createHash('sha256').update(x).digest('hex');
const deny = (): never => {
  throw Error('NATIVE_PUBLIC_RELEASE_DENIED');
};
export type NativePublicationState =
  | 'PREPARED_NO_REMOTE_EFFECT'
  | 'DISPATCHING_UNKNOWN'
  | 'APPLIED_VERIFIED'
  | 'REJECTED_NO_DISPATCH'
  | 'UNKNOWN';
export type NativePublicationBinding = {
  nativeActionId: string;
  actionRevision: number;
  grantId: string;
  grantRevision: number;
  domainId: string;
  principalId: string;
  partnerId: string;
  connectionId: string;
  generation: string;
  chatId: string;
  eventId: string;
  runId: string;
  effectSlot: string;
  epoch: number;
  resourceFingerprint: string;
  completedOutputSha256: string;
  artifactSha256: string | null;
  publisherBindingSha256: string | null;
  artifactRelative: string;
  expiresAt: number;
};
export type PublicationEffect =
  'remote-staging-prepare' | 'remote-staging-upload' | 'remote-transaction';
const steps: readonly PublicationEffect[] = publicationEffects;
export interface NativePublicationRecord extends NativePublicationBinding {
  schema: 'native-publication-action/v1';
  pluginId: string;
  sourceOutputMessageId: string;
  sourceInputSha256: string;
  state: NativePublicationState;
  stateRevision: number;
  runtimeIdentity: string;
  effects: PublicationEffect[];
  publicUrl: string | null;
  receiptSha256: string | null;
  createdAt: number;
  publicNonPersonal: true;
  artifactApprovalSha256: string | null;
  audit: Array<{
    from: NativePublicationState | null;
    to: NativePublicationState;
    at: number;
    stateRevision: number;
  }>;
}
export interface NativePublicationReceipt {
  schema: string;
  nativeActionId: string;
  actionRevision: number;
  grantId: string;
  grantRevision: number;
  completedOutputSha256: string;
  artifactSha256: string;
  publisherBindingSha256: string;
  artifactRelative: string;
  dispatcher: string;
  delivery_state: 'applied' | 'queued' | 'unknown' | 'rejected';
  remoteReleaseId: string | null;
  verifiedSha256: string | null;
  public_url_verified: boolean;
  observedAt: string;
  receiptSha256: string;
}
export interface NativePublisherRuntime {
  /** Main-registered exact code/policy identity. No wire caller may supply this object. */
  identity: string;
  publicOrigin: string;
  dispatcher: string;
  verify(): Promise<void>;
  stage(
    record: NativePublicationRecord,
    text: string,
    control: NativePublicationControl,
  ): Promise<void>;
  apply(
    record: NativePublicationRecord,
    control: NativePublicationControl,
  ): Promise<NativePublicationReceipt>;
  reconcile(record: NativePublicationRecord): Promise<NativePublicationReceipt>;
  /** Main owns dispatch. A root child's request/ACK is never itself permission or execution proof. */
  dispatch(record: NativePublicationRecord, effect: PublicationEffect): Promise<unknown>;
  inspect(record: NativePublicationRecord): Promise<{
    artifactSha256: string;
    publisherBindingSha256: string;
    completedOutputSha256: string;
    artifactRelative: string;
  }>;
}
export interface NativePublicationControl {
  stageBind(): Promise<NativePublicationRecord>;
  beforeEffect(effect: PublicationEffect): Promise<unknown>;
  settle(receipt: NativePublicationReceipt): Promise<NativePublicationRecord>;
}
export interface NativePublicationOwnerInput {
  pluginId: string;
  partnerId: string;
  principalId: string;
  runId: string;
  outputMessageId: string;
  output: string;
  outputSha256: string;
  target: 'canonical-public-report';
  disclosure: 'PUBLIC_RELEASE';
  publicOrigin: string;
  runtimeIdentity?: string;
  artifact?: { sha256: string; publisherBindingSha256: string; relative: string };
  assertCurrent(): void;
}
const pending = new WeakMap<object, Set<string>>();
const running = new WeakMap<object, Set<string>>();
export function createNativePublicationAuthority(
  db: DbClient,
  pluginId: string,
  readOwner: () => void,
  current: (g: RestrictedPartnerGrant) => void,
  ports: {
    readGrant(id: string): Promise<RestrictedPartnerGrant | undefined>;
    readRun(runId: string): Promise<RestrictedPartnerClaim | undefined>;
    approve(
      input: NativePublicationOwnerInput,
    ): Promise<{ approved: boolean; publicNonPersonal: boolean }>;
    runtime(): NativePublisherRuntime | undefined;
    now?: () => number;
  },
) {
  const now = ports.now ?? Date.now;
  const row = async (actionId: string) => {
    readOwner();
    const [r] = await db.drizzle
      .select()
      .from(pluginTaskRequests)
      .where(
        and(
          eq(pluginTaskRequests.id, 'native-publication:' + actionId),
          eq(pluginTaskRequests.pluginId, pluginId),
          eq(pluginTaskRequests.operation, 'target'),
        ),
      )
      .limit(1);
    readOwner();
    return r;
  };
  const record = async (actionId: string) => {
    if (typeof actionId !== 'string' || !/^[a-f0-9-]{36}$/.test(actionId)) deny();
    const r = await row(actionId);
    if (!r) deny();
    const a = JSON.parse(r!.payload) as NativePublicationRecord;
    const states = [
      'PREPARED_NO_REMOTE_EFFECT',
      'DISPATCHING_UNKNOWN',
      'APPLIED_VERIFIED',
      'REJECTED_NO_DISPATCH',
      'UNKNOWN',
    ];
    if (
      a.schema !== 'native-publication-action/v1' ||
      a.pluginId !== pluginId ||
      a.nativeActionId !== actionId ||
      a.actionRevision !== 1 ||
      a.stateRevision !== r!.revision ||
      r!.fingerprint !== publicationSha(a) ||
      !states.includes(a.state) ||
      a.publicNonPersonal !== true ||
      !Array.isArray(a.effects) ||
      a.effects.length > 3 ||
      a.effects.some((e, i) => e !== steps[i]) ||
      !Array.isArray(a.audit) ||
      a.audit.length < 1 ||
      a.audit.length > 32 ||
      a.audit.some(
        (e, i) =>
          e.stateRevision !== i + 1 ||
          !states.includes(e.to) ||
          !Number.isFinite(e.at) ||
          (i === 0 ? e.from !== null : e.from !== a.audit[i - 1].to),
      ) ||
      a.audit.at(-1)!.to !== a.state ||
      a.audit.at(-1)!.stateRevision !== a.stateRevision ||
      !/^core\/imessage\/imessage-[a-f0-9]{32}\.html$/.test(a.artifactRelative) ||
      [a.completedOutputSha256, a.sourceInputSha256, a.runtimeIdentity, a.resourceFingerprint].some(
        (x) => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x),
      ) ||
      [a.artifactSha256, a.publisherBindingSha256, a.receiptSha256, a.artifactApprovalSha256].some(
        (x) => x !== null && (typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x)),
      )
    )
      deny();
    return a;
  };
  const source = async (g: RestrictedPartnerGrant, runId: string) => {
    current(g);
    const fresh = await ports.readGrant(g.id);
    current(g);
    if (publicationCanonical(fresh) !== publicationCanonical(g) || !g.enabled || !g.dispatchEnabled)
      deny();
    const c = await ports.readRun(runId);
    current(g);
    if (
      !c ||
      c.state !== 'COMPLETE' ||
      c.pluginId !== pluginId ||
      c.principalId !== g.principalId ||
      c.partnerId !== g.partnerId ||
      c.grantId !== g.id ||
      c.grantRevision !== g.revision ||
      !c.channel ||
      c.channel.epoch !== g.dispatchEpoch ||
      !c.output ||
      !c.outputMessageId ||
      !c.nativeThreadId ||
      !c.laneSessionId ||
      Buffer.byteLength(c.output) > 32000 ||
      Buffer.from(c.output).toString('utf8') !== c.output ||
      shaText(JSON.stringify([c.channel.domainId, c.channel.principalId])) !== g.principalId
    )
      deny();
    return c!;
  };
  const live = async (g: RestrictedPartnerGrant, a: NativePublicationRecord) => {
    const c = await source(g, a.runId);
    if (
      a.grantId !== g.id ||
      a.grantRevision !== g.revision ||
      a.epoch !== g.dispatchEpoch ||
      a.resourceFingerprint !== grantResourceFingerprint(g) ||
      a.completedOutputSha256 !== shaText(c.output!) ||
      a.sourceOutputMessageId !== c.outputMessageId ||
      a.sourceInputSha256 !== c.inputSha256 ||
      a.expiresAt <= now() ||
      a.createdAt > now() ||
      publicationSha([
        c.channel!.domainId,
        c.channel!.connectionId,
        c.channel!.generation,
        c.channel!.chatId,
        c.channel!.eventId,
      ]) !== publicationSha([a.domainId, a.connectionId, a.generation, a.chatId, a.eventId])
    )
      deny();
    const runtime = ports.runtime();
    if (!runtime || runtime.identity !== a.runtimeIdentity)
      throw Error('NATIVE_PUBLICATION_RUNTIME_UNAVAILABLE');
    await runtime.verify();
    current(g);
    return runtime;
  };
  const cas = async (
    old: NativePublicationRecord,
    next: NativePublicationRecord,
    g?: RestrictedPartnerGrant,
  ) => {
    readOwner();
    if (g) current(g);
    if (next.stateRevision !== old.stateRevision + 1 || old.audit.length >= 32) deny();
    const persisted = {
      ...next,
      audit: [
        ...old.audit,
        { from: old.state, to: next.state, at: now(), stateRevision: next.stateRevision },
      ],
    };
    const expected = JSON.stringify(old),
      payload = JSON.stringify(persisted);
    const result = await db.exec(
      `UPDATE plugin_task_requests SET payload=?,fingerprint=?,revision=? WHERE id=? AND plugin_id=? AND operation='target' AND payload=? AND revision=?${g ? " AND EXISTS (SELECT 1 FROM plugin_task_requests AS grant_row WHERE grant_row.plugin_id=? AND grant_row.operation='target' AND grant_row.target_id=? AND grant_row.payload=?)" : ''}`,
      [
        payload,
        publicationSha(persisted),
        persisted.stateRevision,
        'native-publication:' + old.nativeActionId,
        pluginId,
        expected,
        old.stateRevision,
        ...(g ? [pluginId, 'restricted:grant:' + g.id, JSON.stringify(g)] : []),
      ],
    );
    readOwner();
    if (g) current(g);
    if (result.changes !== 1) throw Error('NATIVE_PUBLICATION_CONFLICT');
    return persisted;
  };
  const failUnknown = async (id: string) => {
    const a = await record(id);
    if (
      a.state === 'APPLIED_VERIFIED' ||
      a.state === 'UNKNOWN' ||
      a.state === 'REJECTED_NO_DISPATCH'
    )
      return a;
    return cas(a, { ...a, state: 'UNKNOWN', stateRevision: a.stateRevision + 1, publicUrl: null });
  };
  const validateReceipt = (
    a: NativePublicationRecord,
    r: NativePublicationReceipt,
    runtime: NativePublisherRuntime,
  ) => {
    const required = [
      'schema',
      'nativeActionId',
      'actionRevision',
      'grantId',
      'grantRevision',
      'completedOutputSha256',
      'artifactSha256',
      'publisherBindingSha256',
      'artifactRelative',
      'dispatcher',
      'delivery_state',
      'remoteReleaseId',
      'verifiedSha256',
      'public_url_verified',
      'observedAt',
      'receiptSha256',
    ];
    if (
      !r ||
      Object.keys(r).length !== required.length ||
      required.some((k) => !(k in r)) ||
      r.schema !== nativeWireSchema ||
      r.dispatcher !== runtime.dispatcher ||
      typeof r.observedAt !== 'string' ||
      !/^\d{4}-.*(?:Z|[+-]\d{2}:\d{2})$/.test(r.observedAt) ||
      !Number.isFinite(Date.parse(r.observedAt)) ||
      Date.parse(r.observedAt) < a.createdAt ||
      Date.parse(r.observedAt) > now() + 60000 ||
      r.receiptSha256 !==
        publicationSha(Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'receiptSha256')))
    )
      deny();
    for (const k of [
      'nativeActionId',
      'actionRevision',
      'grantId',
      'grantRevision',
      'completedOutputSha256',
      'artifactSha256',
      'publisherBindingSha256',
      'artifactRelative',
    ] as const)
      if (r[k] !== a[k]) deny();
    if (
      !['applied', 'queued', 'unknown', 'rejected'].includes(r.delivery_state) ||
      typeof r.public_url_verified !== 'boolean' ||
      (r.remoteReleaseId !== null && typeof r.remoteReleaseId !== 'string') ||
      (r.verifiedSha256 !== null &&
        (typeof r.verifiedSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.verifiedSha256)))
    )
      deny();
    if (r.delivery_state === 'applied') {
      if (
        a.effects.length !== 3 ||
        r.remoteReleaseId !== releaseId(wireBinding(a)) ||
        r.verifiedSha256 !== a.artifactSha256 ||
        r.public_url_verified !== true
      )
        deny();
    } else if (r.public_url_verified !== false) deny();
  };
  const readPublic = async (g: RestrictedPartnerGrant, id: string) => {
    const a = await record(id);
    if (a.principalId !== g.principalId || a.grantId !== g.id) deny();
    let returnAllowed = false,
      runtimeReady = false;
    try {
      const runtime = await live(g, a);
      runtimeReady = true;
      returnAllowed =
        a.state === 'APPLIED_VERIFIED' &&
        a.publicUrl === runtime.publicOrigin + '/reports/' + a.artifactRelative;
    } catch {
      /* Historical effect remains readable; no implicit return grant. */
    }
    return {
      nativeActionId: a.nativeActionId,
      actionRevision: a.actionRevision,
      state: a.state,
      completedOutputSha256: a.completedOutputSha256,
      artifactSha256: a.artifactSha256,
      publisherBindingSha256: a.publisherBindingSha256,
      artifactRelative: a.artifactRelative,
      expiresAt: a.expiresAt,
      runtimeReady,
      returnAllowed,
      publicUrl: returnAllowed ? a.publicUrl : null,
    };
  };
  const service = {
    async lookup(g: RestrictedPartnerGrant, runId: string) {
      readOwner();
      const c = await ports.readRun(runId);
      readOwner();
      if (
        !c ||
        c.state !== 'COMPLETE' ||
        !c.output ||
        !c.outputMessageId ||
        c.pluginId !== pluginId ||
        c.grantId !== g.id ||
        c.principalId !== g.principalId ||
        c.partnerId !== g.partnerId
      )
        deny();
      const key =
        'restricted:publication:' +
        publicationSha([
          pluginId,
          g.principalId,
          g.partnerId,
          runId,
          c!.outputMessageId!,
          shaText(c!.output!),
          'PUBLIC_RELEASE',
        ]);
      const [r] = await db.drizzle
        .select()
        .from(pluginTaskRequests)
        .where(
          and(
            eq(pluginTaskRequests.pluginId, pluginId),
            eq(pluginTaskRequests.operation, 'target'),
            eq(pluginTaskRequests.targetId, key),
          ),
        )
        .limit(1);
      readOwner();
      if (!r) return { state: 'NOT_OBSERVED', publicUrl: null, returnAllowed: false };
      const a = JSON.parse(r.payload) as NativePublicationRecord;
      return readPublic(g, a.nativeActionId);
    },
    async prepare(g: RestrictedPartnerGrant, runId: string) {
      const c = await source(g, runId),
        runtime = ports.runtime();
      if (!runtime) throw Error('NATIVE_PUBLICATION_RUNTIME_UNAVAILABLE');
      const origin = new URL(runtime.publicOrigin);
      if (
        origin.protocol !== 'https:' ||
        origin.origin !== runtime.publicOrigin ||
        origin.username ||
        origin.password ||
        !/^([a-f0-9]{64})$/.test(runtime.identity)
      )
        deny();
      await runtime.verify();
      current(g);
      const outputSha = shaText(c.output!),
        key =
          'restricted:publication:' +
          publicationSha([
            pluginId,
            g.principalId,
            g.partnerId,
            runId,
            c.outputMessageId,
            outputSha,
            'PUBLIC_RELEASE',
          ]);
      const [existing] = await db.drizzle
        .select()
        .from(pluginTaskRequests)
        .where(
          and(
            eq(pluginTaskRequests.pluginId, pluginId),
            eq(pluginTaskRequests.operation, 'target'),
            eq(pluginTaskRequests.targetId, key),
          ),
        )
        .limit(1);
      current(g);
      if (existing) return JSON.parse(existing.payload) as NativePublicationRecord;
      let waits = pending.get(db);
      if (!waits) {
        waits = new Set();
        pending.set(db, waits);
      }
      if (waits.has(key)) throw Error('NATIVE_PUBLICATION_PENDING');
      waits.add(key);
      try {
        const approved = await ports.approve({
          pluginId,
          partnerId: g.partnerId,
          principalId: g.principalId,
          runId,
          outputMessageId: c.outputMessageId!,
          output: c.output!,
          outputSha256: outputSha,
          target: 'canonical-public-report',
          disclosure: 'PUBLIC_RELEASE',
          publicOrigin: runtime.publicOrigin,
          assertCurrent: () => current(g),
        });
        current(g);
        if (!approved.approved || approved.publicNonPersonal !== true) deny();
        const fresh = await source(g, runId);
        if (
          publicationCanonical(fresh) !== publicationCanonical(c) ||
          ports.runtime()?.identity !== runtime.identity
        )
          deny();
        const nativeActionId = randomUUID(),
          createdAt = now();
        const a: NativePublicationRecord = {
          schema: 'native-publication-action/v1',
          pluginId,
          nativeActionId,
          actionRevision: 1,
          grantId: g.id,
          grantRevision: g.revision,
          domainId: c.channel!.domainId,
          principalId: g.principalId,
          partnerId: g.partnerId,
          connectionId: c.channel!.connectionId,
          generation: c.channel!.generation,
          chatId: c.channel!.chatId,
          eventId: c.channel!.eventId,
          runId,
          effectSlot: 'public-release:' + publicationSha(nativeActionId),
          epoch: g.dispatchEpoch,
          resourceFingerprint: grantResourceFingerprint(g),
          completedOutputSha256: outputSha,
          sourceOutputMessageId: c.outputMessageId!,
          sourceInputSha256: c.inputSha256,
          artifactSha256: null,
          publisherBindingSha256: null,
          artifactRelative:
            'core/imessage/imessage-' +
            publicationSha([nativeActionId, g.id, runId, outputSha]).slice(0, 32) +
            '.html',
          expiresAt: createdAt + 600000,
          createdAt,
          state: 'PREPARED_NO_REMOTE_EFFECT',
          stateRevision: 1,
          runtimeIdentity: runtime.identity,
          effects: [],
          publicUrl: null,
          receiptSha256: null,
          publicNonPersonal: true,
          artifactApprovalSha256: null,
          audit: [{ from: null, to: 'PREPARED_NO_REMOTE_EFFECT', at: createdAt, stateRevision: 1 }],
        };
        a.artifactRelative =
          'core/imessage/imessage-' +
          publicMarker(wireBinding(a)).binding_digest.slice(0, 32) +
          '.html';
        const raw = JSON.stringify(a);
        const inserted = await db.exec(
          `INSERT INTO plugin_task_requests(id,plugin_id,operation,target_id,request_key,fingerprint,payload,revision,created_at) SELECT ?,?,'target',?,?,?,?,1,? WHERE EXISTS(SELECT 1 FROM plugin_task_requests WHERE plugin_id=? AND operation='target' AND target_id=? AND payload=?) AND EXISTS(SELECT 1 FROM plugin_task_requests WHERE plugin_id=? AND operation='target' AND target_id=? AND payload=?) ON CONFLICT DO NOTHING`,
          [
            'native-publication:' + nativeActionId,
            pluginId,
            key,
            key,
            publicationSha(a),
            raw,
            createdAt,
            pluginId,
            'restricted:grant:' + g.id,
            JSON.stringify(g),
            pluginId,
            'restricted:input:' + c.inputId,
            JSON.stringify(c),
          ],
        );
        current(g);
        if (inserted.changes !== 1) throw Error('NATIVE_PUBLICATION_CONFLICT');
        return a;
      } finally {
        waits.delete(key);
      }
    },
    record,
    async run(g: RestrictedPartnerGrant, id: string) {
      let a = await record(id);
      if (a.principalId !== g.principalId) deny();
      const runtime = await live(g, a);
      if (a.state !== 'PREPARED_NO_REMOTE_EFFECT') return { state: 'HELD', nativeActionId: id };
      let active = running.get(db);
      if (!active) {
        active = new Set();
        running.set(db, active);
      }
      if (active.has(id)) return { state: 'HELD', nativeActionId: id };
      active.add(id);
      let sourceClaim: RestrictedPartnerClaim;
      try {
        sourceClaim = await source(g, a.runId);
      } catch (error) {
        active.delete(id);
        throw error;
      }
      let sessionActive = true;
      const control: NativePublicationControl = {
        stageBind: async () => {
          if (!sessionActive) deny();
          a = await record(id);
          await live(g, a);
          if (a.state !== 'PREPARED_NO_REMOTE_EFFECT') deny();
          const staged = await runtime.inspect(a);
          await live(g, a);
          if (
            staged.artifactRelative !== a.artifactRelative ||
            staged.completedOutputSha256 !== a.completedOutputSha256 ||
            [staged.artifactSha256, staged.publisherBindingSha256].some(
              (x) => !/^[a-f0-9]{64}$/.test(x),
            )
          )
            deny();
          if (a.artifactSha256 !== null) {
            if (
              staged.artifactSha256 !== a.artifactSha256 ||
              staged.publisherBindingSha256 !== a.publisherBindingSha256 ||
              a.artifactApprovalSha256 !== publicationSha(wireBinding(a))
            )
              deny();
            return a;
          }
          const final = { ...a, ...staged };
          const claim = await source(g, a.runId);
          const approved = await ports.approve({
            pluginId,
            partnerId: g.partnerId,
            principalId: g.principalId,
            runId: a.runId,
            outputMessageId: claim.outputMessageId!,
            output: claim.output!,
            outputSha256: a.completedOutputSha256,
            target: 'canonical-public-report',
            disclosure: 'PUBLIC_RELEASE',
            publicOrigin: runtime.publicOrigin,
            runtimeIdentity: runtime.identity,
            artifact: {
              sha256: staged.artifactSha256,
              publisherBindingSha256: staged.publisherBindingSha256,
              relative: a.artifactRelative,
            },
            assertCurrent: () => current(g),
          });
          await live(g, a);
          if (!approved.approved || approved.publicNonPersonal !== true) deny();
          const after = await runtime.inspect(a);
          await live(g, a);
          if (publicationCanonical(after) !== publicationCanonical(staged)) deny();
          a = await cas(
            a,
            {
              ...final,
              artifactApprovalSha256: publicationSha(wireBinding(final)),
              stateRevision: a.stateRevision + 1,
            },
            g,
          );
          return a;
        },
        beforeEffect: async (effect) => {
          if (!sessionActive) deny();
          a = await record(id);
          await live(g, a);
          if (
            !a.artifactSha256 ||
            !a.publisherBindingSha256 ||
            a.artifactApprovalSha256 !== publicationSha(wireBinding(a)) ||
            !['PREPARED_NO_REMOTE_EFFECT', 'DISPATCHING_UNKNOWN'].includes(a.state) ||
            effect !== steps[a.effects.length]
          )
            deny();
          const staged = await runtime.inspect(a);
          await live(g, a);
          if (
            staged.artifactSha256 !== a.artifactSha256 ||
            staged.publisherBindingSha256 !== a.publisherBindingSha256 ||
            staged.completedOutputSha256 !== a.completedOutputSha256 ||
            staged.artifactRelative !== a.artifactRelative
          )
            deny();
          a = await cas(
            a,
            {
              ...a,
              state: 'DISPATCHING_UNKNOWN',
              stateRevision: a.stateRevision + 1,
              effects: [...a.effects, effect],
            },
            g,
          );
          await live(g, a);
          return runtime.dispatch(a, effect);
        },
        settle: async (receipt) => {
          if (!sessionActive) deny();
          a = await record(id);
          readOwner();
          validateReceipt(a, receipt, runtime);
          if (a.receiptSha256 === receipt.receiptSha256) return a;
          if (a.state === 'APPLIED_VERIFIED') deny();
          const state =
            receipt.delivery_state === 'applied'
              ? 'APPLIED_VERIFIED'
              : receipt.delivery_state === 'rejected' && a.effects.length === 0
                ? 'REJECTED_NO_DISPATCH'
                : 'UNKNOWN';
          a = await cas(a, {
            ...a,
            state,
            stateRevision: a.stateRevision + 1,
            publicUrl:
              state === 'APPLIED_VERIFIED'
                ? runtime.publicOrigin + '/reports/' + a.artifactRelative
                : null,
            receiptSha256: receipt.receiptSha256,
          });
          return a;
        },
      };
      try {
        if (a.artifactSha256 === null) await runtime.stage(a, sourceClaim.output!, control);
        a = await record(id);
        await live(g, a);
        const receipt = await runtime.apply(a, control);
        await control.settle(receipt);
        return await record(id);
      } catch {
        await failUnknown(id);
        throw Error('NATIVE_PUBLICATION_UNKNOWN');
      } finally {
        sessionActive = false;
        active.delete(id);
      }
    },
    async reconcile(g: RestrictedPartnerGrant, id: string) {
      const a = await record(id);
      readOwner();
      if (a.principalId !== g.principalId || a.grantId !== g.id) deny();
      const runtime = ports.runtime();
      if (!runtime || runtime.identity !== a.runtimeIdentity)
        throw Error('NATIVE_PUBLICATION_RUNTIME_UNAVAILABLE');
      if (!['UNKNOWN', 'DISPATCHING_UNKNOWN'].includes(a.state)) return a;
      const receipt = await runtime.reconcile(a);
      readOwner();
      validateReceipt(a, receipt, runtime);
      return cas(a, {
        ...a,
        state: receipt.delivery_state === 'applied' ? 'APPLIED_VERIFIED' : 'UNKNOWN',
        stateRevision: a.stateRevision + 1,
        publicUrl:
          receipt.delivery_state === 'applied'
            ? runtime.publicOrigin + '/reports/' + a.artifactRelative
            : null,
        receiptSha256: receipt.receiptSha256,
      });
    },
    read: readPublic,
  };
  return service;
}
