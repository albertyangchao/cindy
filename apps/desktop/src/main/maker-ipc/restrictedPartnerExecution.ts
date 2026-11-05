import { createHash, randomUUID } from 'node:crypto';
import { RESTRICTED_PARTNER, mintRestrictedPartnerInput } from '@cindy/maker-core';
import type {
  AgentSessionHandle,
  StartSessionOptions,
  RestrictedPartnerTool,
} from '@cindy/maker-core';

/** Candidate Main authority. Neither plugin text nor an ordinary target receipt can mint this grant. */
export interface RestrictedPartnerGrant {
  version: 1;
  id: string;
  revision: number;
  pluginId: string;
  principalId: string;
  partnerId: string;
  enabled: boolean;
  personaSha256: string;
  resourceIds: string[];
  approvalRevision: string;
  resources: Array<{ id: string; path: string }>;
  dispatchEpoch: number;
  dispatchEnabled: boolean;
}
export interface RestrictedPartnerClaim {
  version: 1;
  runId: string;
  inputId: string;
  pluginId: string;
  principalId: string;
  partnerId: string;
  grantId: string;
  grantRevision: number;
  inputSha256: string;
  state: 'UNKNOWN' | 'COMPLETE';
  nativeThreadId?: string;
  routeFingerprint?: string;
  outputMessageId?: string;
  output?: string;
}
export interface RestrictedPartnerPorts {
  /** Captured account/install identity; synchronous invalidation used by native dispatch/read handlers. */
  assertCurrent(grant: RestrictedPartnerGrant): void;
  readGrant(id: string): Promise<RestrictedPartnerGrant | undefined>;
  /** Exact existing active partner, approved persona and separately scoped memory/resources only. */
  project(
    grant: RestrictedPartnerGrant,
  ): Promise<{
    persona: string;
    subjectContext: string;
    readPaths: string[];
    tools?: RestrictedPartnerTool[];
  }>;
  /** Must reject incompatible/remote runners; no default route or owner context fallback. */
  route(
    partnerId: string,
  ): Promise<Pick<StartSessionOptions, 'model' | 'providerId' | 'workingDir' | 'effort'>>;
  start(opts: StartSessionOptions): Promise<AgentSessionHandle>;
  onReserved?(claim: RestrictedPartnerClaim): void;
  readClaim(pluginId: string, inputId: string): Promise<RestrictedPartnerClaim | undefined>;
  /** Unique durable insert; must commit UNKNOWN before start/turn effects. */
  reserve(claim: RestrictedPartnerClaim): Promise<boolean>;
  /** Exact run CAS; an unknown cannot be reconstructed/replayed from text or logs. */
  recordExecution(
    runId: string,
    nativeThreadId: string,
    routeFingerprint: string,
  ): Promise<boolean>;
  recordResult(runId: string, outputMessageId: string, output: string): Promise<boolean>;
  complete(runId: string): Promise<boolean>;
}
const sha = (value: string) => createHash('sha256').update(value).digest('hex');
const fail = (code: string): never => {
  throw new Error(code);
};
const id = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,200}$/.test(value);
export function validGrant(g: RestrictedPartnerGrant | undefined): asserts g is RestrictedPartnerGrant {
  if (
    !g ||
    g.version !== 1 ||
    g.enabled !== true ||
    !Number.isSafeInteger(g.revision) ||
    g.revision < 1 ||
    ![g.id, g.pluginId, g.partnerId, g.principalId].every(id) ||
    !/^[a-f0-9]{64}$/.test(g.personaSha256) ||
    !Array.isArray(g.resourceIds) ||
    g.resourceIds.length > 64 ||
    !g.resourceIds.every(id) ||
    new Set(g.resourceIds).size !== g.resourceIds.length ||
    !Number.isSafeInteger(g.dispatchEpoch) ||
    g.dispatchEpoch < 1 ||
    typeof g.dispatchEnabled !== 'boolean' ||
    (typeof g.approvalRevision!=='string' || !g.approvalRevision || g.approvalRevision.length>256) ||
    !Array.isArray(g.resources) ||
    g.resources.length !== g.resourceIds.length ||
    new Set(g.resources.map((r) => r.id)).size !== g.resourceIds.length ||
    g.resources.some(
      (r) =>
        !g.resourceIds.includes(r.id) ||
        typeof r.path !== 'string' ||
        !r.path ||
        r.path.includes('\0'),
    )
  )
    fail('RESTRICTED_PARTNER_GRANT_INVALID');
}
export function createRestrictedPartnerExecution(ports: RestrictedPartnerPorts) {
  const current = async (frozen: RestrictedPartnerGrant) => {
    ports.assertCurrent(frozen);
    const latest = await ports.readGrant(frozen.id);
    ports.assertCurrent(frozen);
    validGrant(latest);
    if (JSON.stringify(latest) !== JSON.stringify(frozen)) fail('RESTRICTED_PARTNER_REVOKED');
  };
  return {
    async run(request: {
      grantId: string;
      pluginId: string;
      principalId: string;
      partnerId: string;
      inputId: string;
      text: string;
    }): Promise<RestrictedPartnerClaim> {
      if (
        ![
          request.grantId,
          request.pluginId,
          request.principalId,
          request.partnerId,
          request.inputId,
        ].every(id) ||
        typeof request.text !== 'string' ||
        !request.text.trim() ||
        request.text.length > 64_000
      )
        fail('RESTRICTED_PARTNER_INPUT_INVALID');
      const found = await ports.readGrant(request.grantId);
      validGrant(found);
      const grant = structuredClone(found);
      if (!grant.dispatchEnabled) fail('RESTRICTED_PARTNER_PAUSED');
      if (
        grant.pluginId !== request.pluginId ||
        grant.principalId !== request.principalId ||
        grant.partnerId !== request.partnerId
      )
        fail('RESTRICTED_PARTNER_SCOPE_DENIED');
      const digest = sha(
        JSON.stringify([
          request.text,
          grant.id,
          grant.revision,
          grant.partnerId,
          grant.principalId,
        ]),
      );
      await current(grant);
      const old = await ports.readClaim(request.pluginId, request.inputId);
      await current(grant);
      if (old) {
        if (
          old.inputSha256 !== digest ||
          old.partnerId !== grant.partnerId ||
          old.principalId !== grant.principalId
        )
          fail('RESTRICTED_PARTNER_INPUT_CONFLICT');
        const { output, ...metadata } = old;
        return old.state === 'COMPLETE' ? old : metadata; // UNKNOWN never authorizes result release/replay.
      }
      const projection = await ports.project(grant);
      await current(grant);
      if (sha(projection.persona) !== grant.personaSha256)
        fail('RESTRICTED_PARTNER_PERSONA_CHANGED');
      const route = await ports.route(grant.partnerId);
      await current(grant);
      const claim: RestrictedPartnerClaim = {
        version: 1,
        runId: randomUUID(),
        inputId: request.inputId,
        pluginId: grant.pluginId,
        principalId: grant.principalId,
        partnerId: grant.partnerId,
        grantId: grant.id,
        grantRevision: grant.revision,
        inputSha256: digest,
        state: 'UNKNOWN',
      };
      const input = mintRestrictedPartnerInput(
        {
          version: 1,
          partnerId: grant.partnerId,
          principalId: grant.principalId,
          grantId: grant.id,
          grantRevision: grant.revision,
          inputId: claim.inputId,
          runId: claim.runId,
        },
        {
          instructions: [projection.persona, projection.subjectContext]
            .filter(Boolean)
            .join('\n\n'),
          readPaths: projection.readPaths,
          tools: projection.tools,
        },
        () => ports.assertCurrent(grant),
      );
      if (!(await ports.reserve(claim))) return fail('RESTRICTED_PARTNER_NO_RESUBMIT');
      ports.onReserved?.(claim);
      await current(grant);
      let handle: AgentSessionHandle | undefined;
      let primary: unknown;
      let output = '';
      let outputMessageId = '';
      try {
        handle = await ports.start({
          ...route,
          sessionId: claim.runId,
          [RESTRICTED_PARTNER]: input,
          makerMemoryEnabled: false,
          permissionMode: 'ask',
        });
        await current(grant);
        if (
          !id(handle.id) ||
          !(await ports.recordExecution(
            claim.runId,
            handle.id,
            sha(
              JSON.stringify([
                'codex',
                route.model,
                route.providerId ?? null,
                route.effort ?? null,
              ]),
            ),
          ))
        )
          fail('RESTRICTED_PARTNER_EXECUTION_IDENTITY_UNKNOWN');
        await current(grant);
        const collecting = (async () => {
          const blocks = new Map<string, { text: string; phase?: string }>();
          let length = 0;
          for await (const event of handle!.events()) {
            await current(grant);
            if (event.type === 'error') fail('RESTRICTED_PARTNER_EXECUTION_UNKNOWN');
            if (event.type === 'text') {
              const data = event.data as {
                text?: unknown;
                agentMessageId?: unknown;
                phase?: unknown; isFullText?:unknown;
              };
              if (
                typeof data.text !== 'string' ||
                !id(data.agentMessageId) ||
                (data.phase !== undefined && !['commentary', 'final'].includes(String(data.phase)))
              )
                fail('RESTRICTED_PARTNER_OUTPUT_INVALID');
              const key = data.agentMessageId as string;
              const old = blocks.get(key) ?? { text: '', phase: data.phase as string | undefined };
              if (old.phase !== undefined && data.phase !== undefined && old.phase !== data.phase)
                fail('RESTRICTED_PARTNER_OUTPUT_INVALID');
              old.phase = (data.phase as string | undefined) ?? old.phase;
              const previousLength=old.text.length;
              old.text=data.isFullText===true ? data.text as string : old.text+(data.text as string);
              length+=old.text.length-previousLength;
              blocks.set(key, old);
              if (length > 256_000) fail('RESTRICTED_PARTNER_OUTPUT_LIMIT');
            }
            if (event.type === 'done') {
              let finals = [...blocks].filter(([, v]) => v.phase === 'final');
              if (finals.length === 0 && blocks.size === 1)
                finals = [...blocks].filter(([, v]) => v.phase === undefined);
              if (finals.length !== 1) fail('RESTRICTED_PARTNER_OUTPUT_INVALID');
              outputMessageId = finals[0]![0];
              return finals[0]![1].text;
            }
          }
          return fail('RESTRICTED_PARTNER_EXECUTION_UNKNOWN');
        })();
        // Observe a rejected collector even if send itself fails; never leave an unhandled promise.
        void collecting.catch(() => undefined);
        await handle.send({ type: 'user', content: request.text }, { throwOnStartFailure: true });
        output = await collecting;
        await current(grant);
        if (!output.trim()) fail('RESTRICTED_PARTNER_EXECUTION_UNKNOWN');
        if (!(await ports.recordResult(claim.runId, outputMessageId, output)))
          fail('RESTRICTED_PARTNER_RESULT_CONFLICT');
      } catch (error) {
        primary = error;
        throw error;
      } finally {
        if (handle)
          try {
            await handle.close();
          } catch {
            if (!primary) fail('RESTRICTED_PARTNER_CLEANUP_UNKNOWN');
          }
      }
      await current(grant);
      if (!(await ports.complete(claim.runId))) fail('RESTRICTED_PARTNER_RESULT_CONFLICT');
      await current(grant);
      const stored = await ports.readClaim(claim.pluginId, claim.inputId);
      await current(grant);
      if (
        stored?.runId !== claim.runId ||
        stored.state !== 'COMPLETE' ||
        stored.outputMessageId !== outputMessageId
      )
        fail('RESTRICTED_PARTNER_RESULT_CONFLICT');
      return stored!;
    },
  };
}
