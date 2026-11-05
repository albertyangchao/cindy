import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { expect, it, vi } from 'vitest';
import type { AgentEvent, AgentSessionHandle } from '@cindy/maker-core';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import {
  createRestrictedPartnerExecution,
  type RestrictedPartnerGrant,
} from '../restrictedPartnerExecution.js';
// Production Main execution + real SQLite receipt adapter; fake only runner delivery.
// Old plugin target tests cover ordinary canonical task dispatch, not this isolated per-input path.
// Minimal grant/persona/input exercise durable UNKNOWN, exact output and revoke/cleanup. DB tier (in-memory).
const hash = (x: string) => createHash('sha256').update(x).digest('hex');
async function fixture() {
  const sqlite = new Database(':memory:');
  sqlite.exec(
    `CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER, UNIQUE(plugin_id,operation,target_id,request_key));`,
  );
  let active = true;
  const guard = () => {
    if (!active) throw Error('REVOKED');
  };
  const db = {
    drizzle: drizzle(sqlite),
    exec: async (sql: string, params: unknown[]) => {
      const r = sqlite.prepare(sql).run(...params);
      return { changes: r.changes, lastInsertRowid: r.lastInsertRowid };
    },
  } as unknown as DbClient;
  const store = createRestrictedPartnerStore(db, guard);
  const grant: RestrictedPartnerGrant = {
    version: 1,
    id: 'grant',
    pluginId: 'plugin',
    principalId: 'subject',
    partnerId: 'bot_existing',
    revision: 1,
    enabled: true,
    approvalRevision: 'install',
    personaSha256: hash('Approved persona'),
    resourceIds: [],
    resources: [],
    dispatchEpoch: 1,
    dispatchEnabled: true,
  };
  expect(await store.compareAndSwapGrant(grant, 0)).toBe(true);
  const events: AgentEvent[] = [
    {
      type: 'text',
      data: { text: 'safe answer', agentMessageId: 'native-output', phase: 'final' },
    },
    { type: 'done', data: {} },
  ];
  const close = vi.fn(async () => {});
  const send = vi.fn(async () => {});
  const start = vi.fn(
    async () =>
      ({
        id: 'native-thread',
        send,
        close,
        async *events() {
          yield* events;
        },
      }) as unknown as AgentSessionHandle,
  );
  const request = {
    grantId: grant.id,
    pluginId: 'plugin',
    principalId: 'subject',
    partnerId: 'bot_existing',
    inputId: 'new-input',
    text: 'Synthetic question',
  };
  const ports = {
    assertCurrent: guard,
    readGrant: () => store.readGrant('plugin', 'grant'),
    readClaim: store.readClaim,
    reserve: store.reserve,
    recordExecution: store.recordExecution,
    recordResult: store.recordResult,
    complete: store.complete,
    project: async () => ({ persona: 'Approved persona', subjectContext: '', readPaths: [] }),
    route: async () => ({ model: 'fixture', workingDir: '/fixture' }),
    start,
  };
  return {
    sqlite,
    store,
    grant,
    events,
    request,
    ports,
    start,
    send,
    close,
    revoke: () => {
      active = false;
    },
  };
}
it('persists exact existing-partner/run/native-output and never resubmits on duplicate', async () => {
  const f = await fixture();
  try {
    const service = createRestrictedPartnerExecution(f.ports);
    const result = await service.run(f.request);
    expect(result).toMatchObject({
      state: 'COMPLETE',
      partnerId: 'bot_existing',
      principalId: 'subject',
      outputMessageId: 'native-output',
      output: 'safe answer',
    });
    expect(await service.run(f.request)).toEqual(result);
    expect(f.start).toHaveBeenCalledOnce();
    expect(f.send).toHaveBeenCalledOnce();
    expect(f.close).toHaveBeenCalledOnce();
    expect(await f.store.complete(result.runId)).toBe(false);
  } finally {
    f.sqlite.close();
  }
});
it.each(['model-throws', 'cleanup-throws', 'revoked', 'bad-output'] as const)(
  'preserves UNKNOWN/no replay: %s',
  async (mode) => {
    const f = await fixture();
    try {
      if (mode === 'model-throws') f.send.mockRejectedValueOnce(Error('synthetic error'));
      if (mode === 'cleanup-throws') f.close.mockRejectedValueOnce(Error('synthetic cleanup'));
      if (mode === 'revoked')
        f.send.mockImplementationOnce(async () => {
          f.revoke();
        });
      if (mode === 'bad-output') f.events[0] = { type: 'text', data: { text: 'unbound output' } };
      const service = createRestrictedPartnerExecution(f.ports);
      await expect(service.run(f.request)).rejects.toThrow();
      const row = JSON.parse(
        (
          f.sqlite
            .prepare(
              "SELECT payload FROM plugin_task_requests WHERE target_id='restricted:input:new-input'",
            )
            .get() as { payload: string }
        ).payload,
      );
      expect(row.state).toBe('UNKNOWN');
      if (mode !== 'revoked') {
        const bytes = JSON.stringify(row);
        expect(await service.run(f.request)).toMatchObject({ state: 'UNKNOWN' });
        expect(f.start).toHaveBeenCalledOnce();
        expect(JSON.stringify(await f.store.readClaim('plugin', 'new-input'))).toBe(bytes);
      }
    } finally {
      f.sqlite.close();
    }
  },
);
it('atomically rejects concurrent same-principal claims and preserves old unknown across regrant', async () => {
  const f = await fixture();
  try {
    const claim = {
      version: 1 as const,
      runId: 'first',
      inputId: 'one',
      pluginId: 'plugin',
      principalId: 'subject',
      partnerId: 'bot_existing',
      grantId: 'grant',
      grantRevision: 1,
      inputSha256: hash('input'),
      state: 'UNKNOWN' as const,
    };
    expect(await f.store.reserve(claim)).toBe(true);
    expect(
      await f.store.reserve({ ...claim, runId: 'second', inputId: 'two', grantRevision: 2 }),
    ).toBe(false);
    expect(
      await f.store.reserve({ ...claim, runId: 'other', inputId: 'three', principalId: 'other' }),
    ).toBe(true);
    expect(f.start).not.toHaveBeenCalled();
  } finally {
    f.sqlite.close();
  }
});
it('rejects scope drift before projection and runner entry', async () => {
  const f = await fixture();
  try {
    const project = vi.fn(f.ports.project);
    const service = createRestrictedPartnerExecution({ ...f.ports, project });
    await expect(service.run({ ...f.request, principalId: 'another' })).rejects.toThrow(
      'SCOPE_DENIED',
    );
    expect(project).not.toHaveBeenCalled();
    expect(f.start).not.toHaveBeenCalled();
  } finally {
    f.sqlite.close();
  }
});
it('preserves the primary execution error when cleanup also fails', async () => {
  const f = await fixture();
  try {
    f.send.mockRejectedValueOnce(Error('PRIMARY'));
    f.close.mockRejectedValueOnce(Error('CLEANUP'));
    await expect(createRestrictedPartnerExecution(f.ports).run(f.request)).rejects.toThrow(
      'PRIMARY',
    );
  } finally {
    f.sqlite.close();
  }
});
it('fails stale owner/grant CAS without altering existing bytes', async () => {
  const f = await fixture();
  try {
    const before = await f.store.readGrant('plugin', 'grant');
    await expect(f.store.compareAndSwapGrant({ ...f.grant, revision: 2 }, 0)).rejects.toThrow(
      'CONFLICT',
    );
    expect(await f.store.compareAndSwapGrant({ ...f.grant, revision: 3 }, 2)).toBe(false);
    expect(await f.store.readGrant('plugin', 'grant')).toEqual(before);
  } finally {
    f.sqlite.close();
  }
});

it('real Codex final-fulltext semantics replace deltas instead of duplicating the answer',async()=>{
 const f=await fixture();try{
  f.events.splice(0, f.events.length,
   {type:'text',data:{text:'safe ',agentMessageId:'native-output',phase:'final',isFinal:false}},
   {type:'text',data:{text:'answer',agentMessageId:'native-output',phase:'final',isFinal:false}},
   {type:'text',data:{text:'safe answer',agentMessageId:'native-output',phase:'final',isFullText:true,isFinal:true}},
   {type:'done',data:{}});
  expect((await createRestrictedPartnerExecution(f.ports).run(f.request)).output).toBe('safe answer');
 }finally{f.sqlite.close();}
});
