import { legacyMemoryNamespaces } from './restrictedPartnerLegacyMemory.js';
import {
  validateRequirements,
  grantResourceFingerprint,
  requirementHash,
  requirementGaps,
  type PartnerRequirements,
} from './restrictedPartnerRequirements.js';
import { promises as fs } from 'node:fs';
import { restrictedPartnerResources } from './restrictedPartnerResources.js';
import { createHash } from 'node:crypto';
import type { AgentSessionHandle, StartSessionOptions } from '@cindy/maker-core';
import type { DbClient } from '../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import {
  createRestrictedPartnerExecution,
  validGrant,
  type RestrictedPartnerGrant,
} from './restrictedPartnerExecution.js';

export interface RestrictedPartnerHostDeps {
  executionReady?(): Promise<boolean>;
  research?: true;
  modelConfiguration?(
    partnerId: string,
    current: () => void,
  ): Promise<{ providerId: string; modelId: string }>;
  mediaConfiguration?(
    partnerId: string,
    current: () => void,
  ): Promise<{ routes: NonNullable<RestrictedPartnerGrant['media']> }>;
  prepare?: import('./restrictedPartnerExecution.js').RestrictedPartnerPorts['prepare'];
  afterComplete?(
    claim: import('./restrictedPartnerExecution.js').RestrictedPartnerClaim,
    text: string,
    current: () => void,
  ): Promise<void>;
  snapshot(): { client: DbClient; assertCurrent(): void };
  approvalRevision(pluginId: string): string | null;
  candidates(): Promise<Array<{ id: string; label: string; detail: string }>>;
  partnerAuthority(id: string): () => void;
  partner(id: string): Promise<{ persona: string; version: number }>;
  route(
    partnerId: string,
  ): Promise<Pick<StartSessionOptions, 'model' | 'providerId' | 'workingDir' | 'effort'>>;
  start(opts: StartSessionOptions): Promise<AgentSessionHandle>;
  /** Native Host UI only; returns exact owner-chosen paths, not wire paths or plugin secrets. */
  confirm(input: {
    pluginId: string;
    principalId: string;
    partnerId: string;
    label: string;
    chooseResources: boolean;
    mediaRoutes?: RestrictedPartnerGrant['media'];
    modelRoute?: RestrictedPartnerGrant['modelRoute'];
    requirements?: PartnerRequirements;
    assertCurrent: () => void;
  }): Promise<{
    approved: boolean;
    paths: string[];
    coverage?: Partial<Record<'workspace' | 'notes' | 'memory', string[]>>;
    legacyNamespace?: string | null;
  }>;
}
const sha = (x: string) => createHash('sha256').update(x).digest('hex');
const id = (x: unknown): x is string => typeof x === 'string' && /^[a-zA-Z0-9_.:-]{1,200}$/.test(x);
const fail = (x: string): never => {
  throw new Error(x);
};
const safeGrant = (g: RestrictedPartnerGrant, ready = false, research = false) => ({
  version: 1,
  grantId: g.id,
  revision: g.revision,
  partnerId: g.partnerId,
  principalId: g.principalId,
  enabled: g.enabled,
  dispatchEpoch: g.dispatchEpoch,
  dispatchEnabled: g.dispatchEnabled,
  resourceCount: g.resourceIds.length,
  personaSha256: g.personaSha256,
  resourceFingerprint: grantResourceFingerprint(g),
  requirementsFingerprint: g.requirements ? requirementHash(g.requirements) : null,
  requirementsRevision: g.requirements?.revision ?? null,
  modelRoute: g.modelRoute ?? null,
  coverage: Object.fromEntries(
    ['workspace', 'notes', 'memory'].map((k) => [
      k,
      g.resourceCoverage?.[k as 'workspace' | 'notes' | 'memory']?.length ?? 0,
    ]),
  ),
  mediaRoutes: g.media ?? {},
  media: Object.fromEntries(
    ['vision', 'draw', 'edit', 'stt', 'tts'].map((k) => [
      k,
      Boolean(g.media?.[k as keyof NonNullable<typeof g.media>]),
    ]),
  ),
  tools: [
    ...(g.resourceIds.length
      ? [
          'partner_resource_read',
          'partner_resource_list',
          'partner_resource_image',
          'partner_resource_search',
        ]
      : []),
    ...(ready ? ['native_codex_readonly'] : []),
    ...(ready && research ? ['partner_research'] : []),
    ...(g.resourceCoverage?.notes?.length ? ['partner_notes_search'] : []),
    ...(g.legacyMemory ? ['partner_memory_search'] : []),
    'partner_history',
    'partner_memory',
    ...(Object.keys(g.media ?? {}).length ? ['partner_media'] : []),
  ],
});
/** Shared entry for the authorized targets pipe. No ordinary-task fallback. */
export function createRestrictedPartnerHost(deps: RestrictedPartnerHostDeps) {
  const revisions = new Map<string, number>();
  const binding = new Set<string>();
  const epochs = new Map<string, number>();
  const jobs = new Map<string, Promise<unknown>>();
  return async (pluginId: string, raw: unknown, authorized: () => void): Promise<unknown> => {
    authorized();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return fail('INVALID_PARAMS');
    const a = raw as Record<string, unknown>;
    const snapshot = deps.snapshot();
    const approval = deps.approvalRevision(pluginId);
    const current = () => {
      authorized();
      snapshot.assertCurrent();
      if (!approval || deps.approvalRevision(pluginId) !== approval) fail('PERMISSION_DENIED');
    };
    current();
    const store = createRestrictedPartnerStore(snapshot.client, current);
    if (a.operation === 'capabilities' && Object.keys(a).length === 1) {
      const ready = process.platform === 'darwin' && (await deps.executionReady?.()) === true;
      current();
      return {
        version: 1,
        execution: ready,
        runner: 'codex',
        supportedNativeVersion: '0.166.0',
        nativeVersionConfirmed: ready,
        nativeIsolation: true,
        files: 'explicit-owner-read-grants',
        history: deps.prepare ? 'native-channel-scoped' : 'per-input-only',
        memory: deps.prepare ? 'subject-persistent-cas' : 'explicit-owner-read-grants',
        tools: deps.prepare ? 'scoped-core-tools' : 'scoped-reads-only',
        credentials: 'host-only',
        egress: 'original-caller-only',
        media: deps.mediaConfiguration ? 'owner-approved-core-routes' : false,
        unsupported: ['unscoped-mcp', 'shell', 'remote-runner', 'claude-code', 'pi'],
        normalTasksFallback: false,
      };
    }
    if (a.operation === 'list' && Object.keys(a).length === 1) {
      const partners = await deps.candidates();
      current();
      return { partners };
    }
    const principalId = a.principalId;
    if (!id(principalId)) return fail('INVALID_PARAMS');
    const grantId = sha(JSON.stringify([pluginId, principalId]));
    if (a.operation === 'bind') {
      if (deps.executionReady && !(await deps.executionReady()))
        return fail('RESTRICTED_PARTNER_NATIVE_VERSION_UNVERIFIED');
      current();
      if (
        Object.keys(a).some(
          (k) =>
            ![
              'operation',
              'principalId',
              'partnerId',
              'expectedRevision',
              'chooseResources',
              'requirements',
            ].includes(k),
        ) ||
        !id(a.partnerId) ||
        !Number.isSafeInteger(a.expectedRevision) ||
        Number(a.expectedRevision) < 0 ||
        (a.chooseResources !== undefined && typeof a.chooseResources !== 'boolean')
      )
        return fail('INVALID_PARAMS');
      if (a.requirements !== undefined) {
        validateRequirements(a.requirements);
        if (a.requirements.principalId !== principalId) return fail('INVALID_PARAMS');
      }
      if (binding.has(grantId)) return fail('TASK_BUSY');
      binding.add(grantId);
      epochs.set(grantId, (epochs.get(grantId) ?? 0) + 1);
      revisions.delete(grantId); // Invalidate old execution before the first async owner dialog/CAS.
      try {
        const partners = await deps.candidates();
        current();
        const partner = partners.find((p) => p.id === a.partnerId);
        if (!partner) return fail('TARGET_UNAVAILABLE');
        const old = await store.readGrant(pluginId, grantId);
        current();
        if ((old?.revision ?? 0) !== a.expectedRevision) return fail('STALE_REVISION');
        const profile = await deps.partner(partner.id);
        if (profile.persona.length > 16000) return fail('TARGET_UNAVAILABLE');
        current();
        const media = await deps.mediaConfiguration?.(partner.id, current);
        const modelRoute = await deps.modelConfiguration?.(partner.id, current);
        current();
        current();
        const decision = await deps.confirm({
          pluginId,
          principalId,
          partnerId: partner.id,
          label: partner.label,
          chooseResources: a.chooseResources === true,
          mediaRoutes: media?.routes,
          modelRoute,
          requirements: a.requirements as PartnerRequirements | undefined,
          assertCurrent: current,
        });
        current();
        if (!decision.approved) return fail('PERMISSION_DENIED');
        const latest = await deps.partner(partner.id);
        current();
        if (profile.version !== latest.version || profile.persona !== latest.persona)
          return fail('STALE_REVISION');
        if (decision.paths.length > 64) return fail('INVALID_PARAMS');
        const coveragePaths = Object.values(decision.coverage ?? {}).flat();
        const canonical = await Promise.all(
          [...decision.paths, ...coveragePaths].map((p) => fs.realpath(p)),
        );
        if (canonical.length > 64) return fail('INVALID_PARAMS');
        current();
        const resources = [...new Set(canonical)].map((p) => ({ id: sha(p), path: p }));
        const coverage: NonNullable<RestrictedPartnerGrant['resourceCoverage']> = {};
        for (const [purpose, paths] of Object.entries(decision.coverage ?? {}))
          coverage[purpose as keyof typeof coverage] = [
            ...new Set(await Promise.all(paths!.map(async (p) => sha(await fs.realpath(p))))),
          ];
        current();
        const grant: RestrictedPartnerGrant = {
          version: 1,
          id: grantId,
          revision: Number(a.expectedRevision) + 1,
          pluginId,
          principalId,
          partnerId: partner.id,
          enabled: true,
          approvalRevision: approval!,
          personaSha256: sha(profile.persona),
          resourceIds: resources.map((r) => r.id),
          resources,
          dispatchEpoch: 1,
          dispatchEnabled: false,
          ...(media ? { media: media.routes } : {}),
          ...(modelRoute ? { modelRoute } : {}),
          ...(a.requirements
            ? {
                requirements: structuredClone(a.requirements as PartnerRequirements),
                resourceCoverage: coverage,
                ...(decision.legacyNamespace !== undefined && coverage.memory?.length === 1
                  ? {
                      legacyMemory: {
                        resourceId: coverage.memory[0],
                        namespace: decision.legacyNamespace,
                      },
                    }
                  : {}),
              }
            : {}),
        };
        validGrant(grant);
        current();
        if (!(await store.compareAndSwapGrant(grant, Number(a.expectedRevision))))
          return fail('STALE_REVISION');
        current();
        revisions.set(grantId, grant.revision);
        return safeGrant(grant, true, deps.research === true);
      } finally {
        binding.delete(grantId);
      }
    }
    const grant = await store.readGrant(pluginId, grantId);
    current();
    validGrant(grant);
    if (!grant || !grant.enabled || grant.approvalRevision !== approval || binding.has(grantId))
      return fail('PERMISSION_DENIED');
    const executionEpoch = epochs.get(grantId) ?? 0;
    const partnerCurrent = deps.partnerAuthority(grant.partnerId);
    const assertGrant = (g: RestrictedPartnerGrant) => {
      current();
      partnerCurrent();
      if (
        (epochs.get(g.id) ?? 0) !== executionEpoch ||
        binding.has(g.id) ||
        revisions.get(g.id) !== g.revision ||
        g.approvalRevision !== approval
      )
        fail('PERMISSION_DENIED');
    };
    const readiness = async () => {
      const ready = (await deps.executionReady?.()) === true;
      assertGrant(grant);
      const facts = safeGrant(grant, ready, deps.research === true);
      const currentMedia = await deps.mediaConfiguration?.(grant.partnerId, () =>
        assertGrant(grant),
      );
      assertGrant(grant);
      facts.media = Object.fromEntries(
        ['vision', 'draw', 'edit', 'stt', 'tts'].map((kind) => {
          const k = kind as keyof NonNullable<RestrictedPartnerGrant['media']>;
          return [
            kind,
            Boolean(
              grant.media?.[k] &&
              JSON.stringify(grant.media[k]) === JSON.stringify(currentMedia?.routes[k]),
            ),
          ];
        }),
      );
      const modelRoute = await deps.modelConfiguration?.(grant.partnerId, () => assertGrant(grant));
      assertGrant(grant);
      const modelAvailable = Boolean(
        grant.modelRoute && JSON.stringify(grant.modelRoute) === JSON.stringify(modelRoute),
      );
      let resourcesAvailable = true;
      for (const resource of grant.resources) {
        try {
          if ((await fs.realpath(resource.path)) !== resource.path) resourcesAvailable = false;
        } catch {
          resourcesAvailable = false;
        }
        assertGrant(grant);
      }
      if (!resourcesAvailable) facts.coverage = { workspace: 0, notes: 0, memory: 0 };
      let legacyAvailable = Boolean(grant.legacyMemory);
      if (grant.legacyMemory) {
        try {
          const resource = grant.resources.find((r) => r.id === grant.legacyMemory!.resourceId);
          if (!resource) legacyAvailable = false;
          else {
            const ns = legacyMemoryNamespaces(resource.path, () => assertGrant(grant));
            if (
              grant.legacyMemory.namespace === null
                ? ns.length > 0
                : !ns.includes(grant.legacyMemory.namespace)
            )
              legacyAvailable = false;
          }
        } catch {
          legacyAvailable = false;
        }
        assertGrant(grant);
      }
      if (!legacyAvailable) facts.tools = facts.tools.filter((t) => t !== 'partner_memory_search');
      return {
        ...facts,
        missingRequirements: grant.requirements
          ? [
              ...(!modelAvailable ? ['model-route'] : []),
              ...grant.requirements.media.filter((k) => facts.media[k] !== true),
              ...requirementGaps(grant.requirements, {
                tools: facts.tools,
                coverage: resourcesAvailable
                  ? { ...grant.resourceCoverage, ...(!legacyAvailable ? { memory: [] } : {}) }
                  : {},
                memory: Boolean(deps.prepare),
                history: Boolean(deps.prepare),
              }),
            ]
          : ['requirements-review'],
      };
    };
    if (revisions.has(grantId) && revisions.get(grantId) !== grant.revision)
      return fail('STALE_REVISION');
    revisions.set(grantId, grant.revision);
    if (
      a.operation === 'binding' &&
      Object.keys(a).every((k) => ['operation', 'principalId'].includes(k))
    ) {
      const unresolvedCount = await store.unresolvedCount(pluginId, principalId);
      assertGrant(grant);
      return { unresolvedCount, ...(await readiness()) };
    }
    if (
      ['fence', 'resume'].includes(String(a.operation)) &&
      Object.keys(a).every((k) => ['operation', 'principalId', 'expectedRevision'].includes(k))
    ) {
      if (a.expectedRevision !== grant.revision) return fail('STALE_REVISION');
      if (
        a.operation === 'resume' &&
        grant.requirements &&
        (await readiness()).missingRequirements.length
      )
        return fail('RESTRICTED_PARTNER_REQUIREMENTS_UNMET');
      revisions.delete(grantId);
      binding.add(grantId);
      epochs.set(grantId, (epochs.get(grantId) ?? 0) + 1);
      try {
        const next = await store.control(grant, a.operation === 'resume');
        current();
        if (!next) return fail('STALE_REVISION');
        revisions.set(grantId, next.revision);
        return { ...safeGrant(next), unknownPreserved: true };
      } finally {
        binding.delete(grantId);
      }
    }
    if (
      a.operation === 'revoke' &&
      Object.keys(a).every((k) => ['operation', 'principalId', 'expectedRevision'].includes(k))
    ) {
      if (a.expectedRevision !== grant.revision) return fail('STALE_REVISION');
      revisions.delete(grantId);
      binding.add(grantId);
      epochs.set(grantId, (epochs.get(grantId) ?? 0) + 1);
      try {
        if (
          !(await store.compareAndSwapGrant(
            { ...grant, enabled: false, revision: grant.revision + 1 },
            grant.revision,
          ))
        )
          return fail('STALE_REVISION');
        current();
        return { revoked: true, revision: grant.revision + 1, unknownPreserved: true };
      } finally {
        binding.delete(grantId);
      }
    }
    if (
      a.operation === 'get' &&
      Object.keys(a).every((k) => ['operation', 'principalId', 'runId'].includes(k)) &&
      id(a.runId)
    ) {
      const claim = await store.byRun(pluginId, a.runId);
      assertGrant(grant);
      if (
        !claim ||
        claim.grantId !== grant.id ||
        claim.grantRevision !== grant.revision ||
        claim.partnerId !== grant.partnerId ||
        claim.principalId !== principalId
      )
        return fail('PERMISSION_DENIED');
      const { output, assets, inputText, ...metadata } = claim;
      const released = { ...metadata, output, assets };
      return {
        ...(claim.state === 'COMPLETE' ? released : metadata),
        runningObserved: jobs.has(claim.runId),
      };
    }
    if (
      a.operation !== 'submit' ||
      Object.keys(a).some(
        (k) =>
          ![
            'operation',
            'principalId',
            'partnerId',
            'grantRevision',
            'inputId',
            'text',
            'channel',
            'assets',
          ].includes(k),
      ) ||
      a.partnerId !== grant.partnerId ||
      a.grantRevision !== grant.revision ||
      !id(a.inputId) ||
      typeof a.text !== 'string'
    )
      return fail('INVALID_PARAMS');
    if (
      grant.requirements &&
      ((await readiness()).missingRequirements.length ||
        (a.channel as { memoryRead?: unknown })?.memoryRead !== true)
    )
      return fail('RESTRICTED_PARTNER_REQUIREMENTS_UNMET');
    if (deps.prepare) {
      const c = a.channel as Record<string, unknown>;
      if (
        !c ||
        Array.isArray(c) ||
        Object.keys(c).some(
          (k) =>
            ![
              'domainId',
              'principalId',
              'connectionId',
              'generation',
              'chatId',
              'eventId',
              'revision',
              'epoch',
              'memoryRead',
            ].includes(k),
        ) ||
        ['domainId', 'principalId', 'connectionId', 'generation', 'chatId', 'eventId'].some(
          (k) =>
            typeof c[k] !== 'string' || !(c[k] as string).length || (c[k] as string).length > 256,
        ) ||
        typeof c.memoryRead !== 'boolean' ||
        !Number.isSafeInteger(c.revision) ||
        Number(c.revision) < 1 ||
        !Number.isSafeInteger(c.epoch) ||
        Number(c.epoch) < 1 ||
        sha(JSON.stringify([c.domainId, c.principalId])) !== principalId ||
        !Array.isArray(a.assets ?? []) ||
        ((a.assets as unknown[]) ?? []).length > 4
      )
        return fail('INVALID_PARAMS');
    }
    if (a.assets !== undefined) {
      if (
        !Array.isArray(a.assets) ||
        a.assets.some((x) => !x || typeof x !== 'object' || Array.isArray(x))
      )
        return fail('INVALID_PARAMS');
      let bytes = 0;
      for (const rawAsset of a.assets) {
        const x = rawAsset as Record<string, unknown>;
        if (
          Object.keys(x).some(
            (k) => !['id', 'sha256', 'mimeType', 'base64', 'sourceSha256', 'partial'].includes(k),
          ) ||
          typeof x.base64 !== 'string' ||
          !x.base64.length ||
          x.base64.length > 6 * 1024 * 1024 ||
          !['image/png', 'audio/wav'].includes(String(x.mimeType)) ||
          typeof x.sha256 !== 'string' ||
          !/^asset:[a-f0-9]{64}$/.test(String(x.id)) ||
          x.id !== 'asset:' + x.sha256 ||
          typeof x.sourceSha256 !== 'string' ||
          !/^[a-f0-9]{64}$/.test(x.sourceSha256) ||
          typeof x.partial !== 'boolean'
        )
          return fail('INVALID_PARAMS');
        bytes += x.base64.length;
      }
      if (bytes > 12 * 1024 * 1024) return fail('INVALID_PARAMS');
    }
    assertGrant(grant);
    // Reservation resolves the pipe before execution; the job's durable UNKNOWN is queryable across calls/restart.
    return new Promise((resolve, reject) => {
      let reserved = false;
      let reservedRun: string | undefined;
      const service = createRestrictedPartnerExecution({
        assertCurrent: assertGrant,
        readGrant: () => store.readGrant(pluginId, grantId),
        readClaim: store.readClaim,
        reserve: store.reserve,
        recordExecution: store.recordExecution,
        recordResult: store.recordResult,
        complete: store.complete,
        project: async (g) => {
          const p = await deps.partner(g.partnerId);
          assertGrant(g);
          const resources = restrictedPartnerResources(g, () => assertGrant(g));
          return {
            persona: p.persona,
            subjectContext: resources.context,
            tools: resources.tools,
            readPaths: [],
          };
        },
        route: async (id) => {
          const route = await deps.route(id);
          assertGrant(grant);
          if (
            grant.modelRoute &&
            (route.model !== grant.modelRoute.modelId ||
              route.providerId !== grant.modelRoute.providerId)
          )
            return fail('RESTRICTED_PARTNER_ROUTE_UNSUPPORTED');
          return route;
        },
        start: deps.start,
        prepare: deps.prepare,
        afterComplete: (claim, text) =>
          deps.afterComplete?.(claim, text, () => assertGrant(grant)) ?? Promise.resolve(),
        onReserved: (claim) => {
          reserved = true;
          reservedRun = claim.runId;
          jobs.set(claim.runId, job);
          resolve({
            version: 1,
            accepted: true,
            runId: claim.runId,
            inputId: claim.inputId,
            partnerId: claim.partnerId,
            grantId: claim.grantId,
            grantRevision: claim.grantRevision,
            state: 'UNKNOWN',
          });
        },
      });
      const job = service
        .run({
          grantId,
          pluginId,
          principalId,
          partnerId: grant.partnerId,
          inputId: a.inputId as string,
          text: a.text as string,
          channel: a.channel as
            import('./restrictedPartnerExecution.js').RestrictedChannelInput | undefined,
          assets: a.assets as
            import('./restrictedPartnerExecution.js').RestrictedInputAsset[] | undefined,
        })
        .then((claim) => {
          if (!reserved)
            resolve({
              version: 1,
              accepted: true,
              duplicate: true,
              runId: claim.runId,
              inputId: claim.inputId,
              partnerId: claim.partnerId,
              grantId: claim.grantId,
              grantRevision: claim.grantRevision,
              state: claim.state,
            });
        })
        .catch((error) => {
          if (!reserved) reject(error);
        })
        .finally(() => {
          if (reservedRun) jobs.delete(reservedRun);
        });
    });
  };
}
