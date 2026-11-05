import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { it, expect } from 'vitest';
import { RESTRICTED_PARTNER, type AgentSessionHandle } from '@cindy/maker-core';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { restrictedPartnerResearch } from '../restrictedPartnerResearch.js';
import {
  createRestrictedPartnerExecution,
  type RestrictedPartnerGrant,
  type RestrictedPartnerClaim,
} from '../restrictedPartnerExecution.js';
import type { DbClient } from '../../localDb/client/DbClient.js';
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
function setup(fail = false) {
  const sql = new Database(':memory:');
  sql.exec(
    'CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key));',
  );
  const db = {
    drizzle: drizzle(sql),
    exec: async (query: string, params: unknown[]) => ({
      changes: sql.prepare(query).run(...params).changes,
    }),
  } as unknown as DbClient;
  let active = true,
    starts = 0,
    reads = 0,
    closed = 0;
  const current = () => {
    if (!active) throw Error('REVOKED');
  };
  const store = createRestrictedPartnerStore(db, current);
  const g: RestrictedPartnerGrant = {
    version: 1,
    id: 'grant',
    revision: 1,
    pluginId: 'plugin',
    principalId: sha(JSON.stringify(['domain', 'subject'])),
    partnerId: 'bot',
    enabled: true,
    personaSha256: sha('Approved'),
    resourceIds: [],
    resources: [],
    approvalRevision: 'a',
    dispatchEpoch: 1,
    dispatchEnabled: true,
  };
  const channel = {
    domainId: 'domain',
    principalId: 'subject',
    connectionId: 'c',
    generation: 'g',
    chatId: 'chat',
    eventId: 'new',
    revision: 1,
    epoch: 1,
    memoryRead: true,
  };
  const parent: RestrictedPartnerClaim = {
    version: 1,
    runId: 'parent',
    inputId: 'parent-input',
    pluginId: 'plugin',
    principalId: g.principalId,
    partnerId: 'bot',
    grantId: 'grant',
    grantRevision: 1,
    inputSha256: sha('parent'),
    state: 'UNKNOWN',
    channel,
  };
  const project = async () => ({
    persona: 'Approved',
    subjectContext: 'Scoped only',
    readPaths: [],
    tools: [
      {
        name: 'partner_resource_search',
        description: 'approved search',
        inputSchema: { type: 'object' },
        invoke: async () => {
          current();
          reads++;
          return {
            success: true,
            contentItems: [{ type: 'inputText' as const, text: 'approved evidence' }],
          };
        },
      },
      {
        name: 'partner_memory',
        description: 'write excluded',
        inputSchema: { type: 'object' },
        invoke: async () => {
          throw Error('must not inherit writable tools');
        },
      },
    ],
  });
  const route = async () => ({ model: 'fixture', providerId: 'fixed', workingDir: '/synthetic' });
  const start = async (opts: any) => {
    starts++;
    expect(opts[RESTRICTED_PARTNER]).toBeTruthy();
    expect(opts[RESTRICTED_PARTNER].tools.map((t: any) => t.name)).toEqual([
      'partner_resource_search',
    ]);
    const rows = sql
      .prepare(
        "SELECT payload FROM plugin_task_requests WHERE target_id LIKE 'restricted:research:%'",
      )
      .all() as Array<{ payload: string }>;
    expect(rows.some((r) => JSON.parse(r.payload).claim.state === 'UNKNOWN')).toBe(true);
    return {
      id: 'native-' + starts,
      send: async () => {
        if (fail) throw Error('SYNTHETIC_RPC_UNKNOWN');
        await opts[RESTRICTED_PARTNER].tools[0].invoke(
          { query: 'evidence' },
          { runId: opts.sessionId, callId: 'read' },
        );
      },
      close: async () => {
        closed++;
      },
      async *events() {
        yield {
          type: 'text',
          data: { text: 'bounded research result', agentMessageId: 'answer', phase: 'final' },
        };
        yield { type: 'done', data: {} };
      },
    } as unknown as AgentSessionHandle;
  };
  return {
    sql,
    db,
    g,
    parent,
    store,
    current,
    project,
    route,
    start,
    stats: () => ({ starts, reads, closed }),
    revoke: () => {
      active = false;
    },
  };
}
it('real receipt/brand/factory uses one readonly native worker; duplicate concurrent prompt does not model/recharge; writable tools excluded', async () => {
  const f = setup();
  try {
    await f.store.compareAndSwapGrant(f.g, 0);
    await f.store.reserve(f.parent);
    const research = restrictedPartnerResearch(f.db, f.g, f.parent, f.current, f);
    const ask = () =>
      research.tool.invoke(
        { prompt: 'analyze approved source' },
        { runId: 'parent', callId: 'ask' },
      );
    const [a, b] = await Promise.all([ask(), ask()]);
    expect(a).toEqual(b);
    expect(JSON.stringify(a)).toContain('bounded research result');
    expect(f.stats()).toEqual({ starts: 1, reads: 1, closed: 1 });
    research.assertResolved();
    await ask();
    expect(f.stats().starts).toBe(1);
    const row = f.sql
      .prepare(
        "SELECT payload FROM plugin_task_requests WHERE target_id LIKE 'restricted:research:%'",
      )
      .get() as { payload: string };
    expect(JSON.parse(row.payload)).toMatchObject({
      parentRunId: 'parent',
      claim: { state: 'COMPLETE', nativeThreadId: 'native-1', outputMessageId: 'answer' },
    });
  } finally {
    f.sql.close();
  }
});
it('uncertain research is durable and cannot be resubmitted or released as a complete parent answer', async () => {
  const f = setup(true);
  try {
    await f.store.compareAndSwapGrant(f.g, 0);
    await f.store.reserve(f.parent);
    const research = restrictedPartnerResearch(f.db, f.g, f.parent, f.current, f);
    const ask = () =>
      research.tool.invoke({ prompt: 'lost result' }, { runId: 'parent', callId: 'ask' });
    await expect(ask()).rejects.toThrow();
    await expect(ask()).rejects.toThrow();
    expect(f.stats().starts).toBe(1);
    expect(() => research.assertResolved()).toThrow('UNKNOWN');
    expect(await f.store.unresolvedCount('plugin', f.g.principalId)).toBe(1);
    f.revoke();
    await expect(ask()).rejects.toThrow('REVOKED');
    expect(f.stats().starts).toBe(1);
  } finally {
    f.sql.close();
  }
});
it('research refuses a non-parent invocation or an unreserved parent before any runner/effect', async () => {
  const f = setup();
  try {
    await f.store.compareAndSwapGrant(f.g, 0);
    const research = restrictedPartnerResearch(f.db, f.g, f.parent, f.current, f);
    await expect(
      research.tool.invoke({ prompt: 'x' }, { runId: 'other', callId: 'x' }),
    ).rejects.toThrow();
    await expect(
      research.tool.invoke({ prompt: 'x' }, { runId: 'parent', callId: 'x' }),
    ).rejects.toThrow();
    expect(f.stats().starts).toBe(0);
    expect(
      f.sql
        .prepare(
          "SELECT count(*) n FROM plugin_task_requests WHERE target_id LIKE 'restricted:research:%'",
        )
        .get(),
    ).toEqual({ n: 0 });
  } finally {
    f.sql.close();
  }
});
