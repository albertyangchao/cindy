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
  }): Promise<{ approved: boolean; paths: string[] }>;
}
const sha = (x: string) => createHash('sha256').update(x).digest('hex');
const id = (x: unknown): x is string => typeof x === 'string' && /^[a-zA-Z0-9_.:-]{1,200}$/.test(x);
const fail = (x: string): never => {
  throw new Error(x);
};
const safeGrant = (g: RestrictedPartnerGrant) => ({
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
    if (a.operation === 'capabilities' && Object.keys(a).length === 1)
      return {
        version: 1,
        execution: process.platform === 'darwin',
        runner: 'codex',
        verifiedNativeVersion: '0.166.0',
        nativeIsolation: true,
        files: 'explicit-owner-read-grants',
        history: 'per-input-only',
        memory: 'explicit-owner-read-grants',
        tools: 'scoped-reads-only',
        credentials: 'host-only',
        egress: 'original-caller-only',
        media: false,
        normalTasksFallback: false,
      };
    if (a.operation === 'list' && Object.keys(a).length === 1) {
      const partners = await deps.candidates();
      current();
      return { partners };
    }
    const principalId = a.principalId;
    if (!id(principalId)) return fail('INVALID_PARAMS');
    const grantId = sha(JSON.stringify([pluginId, principalId]));
    if (a.operation === 'bind') {
      if (
        Object.keys(a).some(
          (k) =>
            ![
              'operation',
              'principalId',
              'partnerId',
              'expectedRevision',
              'chooseResources',
            ].includes(k),
        ) ||
        !id(a.partnerId) ||
        !Number.isSafeInteger(a.expectedRevision) ||
        Number(a.expectedRevision) < 0 ||
        (a.chooseResources !== undefined && typeof a.chooseResources !== 'boolean')
      )
        return fail('INVALID_PARAMS');
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
        current();
        const decision = await deps.confirm({
          pluginId,
          principalId,
          partnerId: partner.id,
          label: partner.label,
          chooseResources: a.chooseResources === true,
        });
        current();
        if (!decision.approved) return fail('PERMISSION_DENIED');
        const latest = await deps.partner(partner.id);
        current();
        if (profile.version !== latest.version || profile.persona !== latest.persona)
          return fail('STALE_REVISION');
        if (decision.paths.length > 64) return fail('INVALID_PARAMS');
        const canonical = await Promise.all(decision.paths.map((p) => fs.realpath(p)));
        current();
        const resources = [...new Set(canonical)].map((p) => ({ id: sha(p), path: p }));
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
        };
        if (!(await store.compareAndSwapGrant(grant, Number(a.expectedRevision))))
          return fail('STALE_REVISION');
        current();
        revisions.set(grantId, grant.revision);
        return safeGrant(grant);
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
    if (revisions.has(grantId) && revisions.get(grantId) !== grant.revision)
      return fail('STALE_REVISION');
    revisions.set(grantId, grant.revision);
    if (
      a.operation === 'binding' &&
      Object.keys(a).every((k) => ['operation', 'principalId'].includes(k))
    )
      return safeGrant(grant);
    if (
      ['fence', 'resume'].includes(String(a.operation)) &&
      Object.keys(a).every((k) => ['operation', 'principalId', 'expectedRevision'].includes(k))
    ) {
      if (a.expectedRevision !== grant.revision) return fail('STALE_REVISION');
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
      const { output, ...metadata } = claim;
      return {
        ...(claim.state === 'COMPLETE' ? claim : metadata),
        runningObserved: jobs.has(claim.runId),
      };
    }
    if (
      a.operation !== 'submit' ||
      Object.keys(a).some(
        (k) =>
          !['operation', 'principalId', 'partnerId', 'grantRevision', 'inputId', 'text'].includes(
            k,
          ),
      ) ||
      a.partnerId !== grant.partnerId ||
      a.grantRevision !== grant.revision ||
      !id(a.inputId) ||
      typeof a.text !== 'string'
    )
      return fail('INVALID_PARAMS');
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
        route: deps.route,
        start: deps.start,
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
