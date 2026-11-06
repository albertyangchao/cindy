import { createHash } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import type { DbClient } from '../localDb/client/DbClient.js';
import { pluginTaskRequests as table } from '../localDb/schema.js';
import {
  createRestrictedPartnerExecution,
  type RestrictedPartnerClaim,
  type RestrictedPartnerGrant,
  type RestrictedPartnerPorts,
} from './restrictedPartnerExecution.js';
import { createRestrictedPartnerStore } from './restrictedPartnerStore.js';
import type { RestrictedPartnerTool } from '@cindy/maker-core';
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
const deny = (): never => {
  throw Error('RESTRICTED_PARTNER_RESEARCH_UNKNOWN');
};
/** Exact replacement for the legacy bounded read-only coder/research call. Reuses the real restricted native runner, never ordinary tasks. */
export function restrictedPartnerResearch(
  db: DbClient,
  g: RestrictedPartnerGrant,
  parent: RestrictedPartnerClaim,
  current: () => void,
  ports: Pick<RestrictedPartnerPorts, 'project' | 'route' | 'start'>,
) {
  const store = createRestrictedPartnerStore(db, current),
    prefix = 'restricted:research:' + parent.runId + ':';
  const jobs = new Map<string, Promise<Awaited<ReturnType<RestrictedPartnerTool['invoke']>>>>(),
    pending = new Set<string>(),
    targets = new Map<string, string>();
  const read = async (inputId: string) => {
    current();
    const [row] = await db.drizzle
      .select()
      .from(table)
      .where(
        and(
          eq(table.pluginId, g.pluginId),
          eq(table.operation, 'target'),
          eq(table.targetId, prefix + inputId),
        ),
      )
      .limit(1);
    current();
    if (!row) return;
    const saved = JSON.parse(row.payload);
    if (
      saved.parentRunId !== parent.runId ||
      saved.grantId !== g.id ||
      saved.grantRevision !== g.revision
    )
      deny();
    if (
      saved.claim.inputId !== inputId ||
      saved.claim.pluginId !== g.pluginId ||
      saved.claim.grantId !== g.id ||
      saved.claim.grantRevision !== g.revision ||
      saved.claim.principalId !== g.principalId ||
      saved.claim.partnerId !== g.partnerId ||
      JSON.stringify(saved.claim.channel) !== JSON.stringify(parent.channel)
    )
      deny();
    targets.set(saved.claim.runId, prefix + inputId);
    return { row, claim: saved.claim as RestrictedPartnerClaim };
  };
  const update = async (
    run: string,
    change: (cl: RestrictedPartnerClaim) => RestrictedPartnerClaim,
  ) => {
    const target = targets.get(run);
    if (!target) deny();
    const before = await read(target!.slice(prefix.length));
    if (!before || before.claim.runId !== run) deny();
    current();
    const after = change(before!.claim),
      payload = JSON.stringify({
        parentRunId: parent.runId,
        grantId: g.id,
        grantRevision: g.revision,
        claim: after,
      });
    const rows = await db.drizzle
      .update(table)
      .set({ payload, revision: before!.row.revision + 1 })
      .where(
        and(
          eq(table.id, before!.row.id),
          eq(table.payload, before!.row.payload),
          eq(table.revision, before!.row.revision),
        ),
      )
      .returning({ id: table.id });
    current();
    return rows.length === 1;
  };
  const tool: RestrictedPartnerTool = {
    name: 'partner_research',
    description:
      'Delegate one bounded read-only code/research question to the actual restricted native Codex worker using only this subject’s approved resources/history. No shell, arbitrary integrations or implicit web access. Repeated same prompt reuses its exact receipt; unknown never resubmits.',
    inputSchema: {
      type: 'object',
      properties: { prompt: { type: 'string', minLength: 1, maxLength: 12000 } },
      required: ['prompt'],
      additionalProperties: false,
    },
    invoke: async (raw, call) => {
      current();
      const a = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, unknown>;
      if (
        !a ||
        Object.keys(a).length !== 1 ||
        typeof a.prompt !== 'string' ||
        !a.prompt.trim() ||
        a.prompt.length > 12000 ||
        call.runId !== parent.runId
      )
        deny();
      const live = await store.byRun(g.pluginId, parent.runId);
      current();
      if (
        !live ||
        live.state !== 'UNKNOWN' ||
        live.grantId !== g.id ||
        live.grantRevision !== g.revision ||
        live.principalId !== g.principalId ||
        live.partnerId !== g.partnerId ||
        live.inputId !== parent.inputId ||
        JSON.stringify(live.channel) !== JSON.stringify(parent.channel)
      )
        deny();
      const prompt = a.prompt as string,
        inputId = hash(JSON.stringify([parent.runId, prompt]));
      if (jobs.has(inputId)) return jobs.get(inputId)!;
      if (jobs.size >= 4) deny();
      pending.add(inputId);
      const service = createRestrictedPartnerExecution({
        assertCurrent: current,
        readGrant: () => store.readGrant(g.pluginId, g.id),
        readClaim: async () => (await read(inputId))?.claim,
        reserve: async (claim) => {
          current();
          const row = {
            id: prefix + inputId,
            pluginId: g.pluginId,
            operation: 'target' as const,
            targetId: prefix + inputId,
            requestKey: inputId,
            fingerprint: claim.inputSha256,
            payload: JSON.stringify({
              parentRunId: parent.runId,
              grantId: g.id,
              grantRevision: g.revision,
              claim,
            }),
            revision: 1,
            createdAt: Date.now(),
          };
          const rows = await db.drizzle
            .insert(table)
            .values(row)
            .onConflictDoNothing()
            .returning({ id: table.id });
          current();
          if (rows.length === 1) targets.set(claim.runId, prefix + inputId);
          return rows.length === 1;
        },
        recordExecution: (run, nativeThreadId, routeFingerprint) =>
          update(run, (c) => ({ ...c, nativeThreadId, routeFingerprint })),
        recordResult: (run, outputMessageId, output) =>
          update(run, (c) => ({ ...c, outputMessageId, output })),
        complete: (run) =>
          update(run, (c) => {
            if (c.state !== 'UNKNOWN' || !c.nativeThreadId || !c.outputMessageId || !c.output)
              deny();
            return { ...c, state: 'COMPLETE' };
          }),
        project: async (grant) => {
          const projected = await ports.project(grant);
          current();
          return {
            ...projected,
            subjectContext:
              projected.subjectContext +
              '\nRead-only research worker: use only supplied scoped tools. No write/media/delegation/web claims.',
            tools: (projected.tools ?? []).filter((t) =>
              [
                'partner_resource_read',
                'partner_resource_list',
                'partner_resource_image',
                'partner_resource_search',
                'partner_notes_search',
                'partner_memory_search',
                'partner_history',
              ].includes(t.name),
            ),
          };
        },
        route: ports.route,
        start: ports.start,
      });
      const work = service
        .run({
          grantId: g.id,
          pluginId: g.pluginId,
          principalId: g.principalId,
          partnerId: g.partnerId,
          inputId,
          text: prompt,
          channel: parent.channel,
        })
        .then((result) => {
          current();
          if (
            result.state !== 'COMPLETE' ||
            !result.output ||
            !result.nativeThreadId ||
            !result.outputMessageId
          )
            deny();
          pending.delete(inputId);
          return {
            success: true,
            contentItems: [
              {
                type: 'inputText' as const,
                text: JSON.stringify({
                  state: 'COMPLETE',
                  parentRunId: parent.runId,
                  researchRunId: result.runId,
                  nativeThreadId: result.nativeThreadId,
                  outputMessageId: result.outputMessageId,
                  text: result.output!.slice(0, 24000),
                  partial: result.output!.length > 24000,
                }),
              },
            ],
          };
        });
      jobs.set(inputId, work);
      void work.catch(() => {});
      return work;
    },
  };
  return {
    tool,
    assertResolved() {
      current();
      if (pending.size) deny();
    },
  };
}
