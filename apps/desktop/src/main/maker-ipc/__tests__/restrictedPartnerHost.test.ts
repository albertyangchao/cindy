import { mkdtemp, realpath, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { expect, it, vi } from 'vitest';
import type { AgentSessionHandle } from '@cindy/maker-core';
import type { DbClient } from '../../localDb/client/DbClient.js';
import {
  type RestrictedPartnerHostDeps,
  createRestrictedPartnerHost,
} from '../restrictedPartnerHost.js';
function fixture(
  ready = true,
  mediaRoutes: Record<string, { providerId: string; modelId: string }> = {},
  extra: Partial<RestrictedPartnerHostDeps> = {},
) {
  const sqlite = new Database(':memory:');
  sqlite.exec(
    `CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key));`,
  );
  const db = {
    drizzle: drizzle(sqlite),
    exec: async (sql: string, params: unknown[]) => ({
      changes: sqlite.prepare(sql).run(...params).changes,
    }),
  } as unknown as DbClient;
  let authorized = true,
    approval = 'approval-1',
    profileCurrent = true;
  const guard = () => {
    if (!authorized) throw Error('DENIED');
  };
  const start = vi.fn(
    async () =>
      ({
        id: 'native-thread',
        send: async () => {},
        close: async () => {},
        async *events() {
          yield {
            type: 'text',
            data: { text: 'synthetic output', agentMessageId: 'native-message', phase: 'final' },
          };
          yield { type: 'done', data: {} };
        },
      }) as unknown as AgentSessionHandle,
  );
  const confirm = vi.fn(async () => ({ approved: true, paths: [] }));
  const host = createRestrictedPartnerHost({
    executionReady: async () => ready,
    mediaConfiguration: async () => ({ routes: mediaRoutes }),
    snapshot: () => ({ client: db, assertCurrent: guard }),
    approvalRevision: () => approval,
    candidates: async () => [{ id: 'bot_real', label: 'Existing synthetic partner', detail: '' }],
    partner: async () => ({ persona: 'Approved persona', version: 1 }),
    partnerAuthority: () => () => {
      if (!profileCurrent) throw Error('PARTNER_CHANGED');
    },
    route: async () => ({
      model: 'fixture',
      providerId: 'fixture-provider',
      workingDir: '/fixture',
    }),
    start,
    confirm,
    ...extra,
  });
  const call = (request: unknown) => host('plugin', request, guard) as Promise<any>;
  return {
    sqlite,
    changeMedia: (next: typeof mediaRoutes) => {
      mediaRoutes = next;
    },
    start,
    confirm,
    call,
    revoke: () => {
      authorized = false;
    },
    profileChange: () => {
      profileCurrent = false;
    },
    approvalChange: () => {
      approval = 'approval-2';
    },
  };
}
const principalId = createHash('sha256').update('synthetic subject').digest('hex');
const bind = { operation: 'bind', principalId, partnerId: 'bot_real', expectedRevision: 0 };
it('actual owner-picked binding stays fenced until explicit resume; exact run/output and duplicate receipt', async () => {
  const f = fixture();
  try {
    const grant = await f.call(bind);
    expect(grant).toMatchObject({ enabled: true, dispatchEnabled: false, revision: 1 });
    const request = {
      operation: 'submit',
      principalId,
      partnerId: 'bot_real',
      grantRevision: 1,
      inputId: 'input',
      text: 'Synthetic question',
    };
    await expect(f.call(request)).rejects.toThrow('PAUSED');
    expect(f.start).not.toHaveBeenCalled();
    await f.call({ operation: 'resume', principalId, expectedRevision: 1 });
    const ack = await f.call(request);
    expect(ack.accepted).toBe(true);
    let read;
    for (let i = 0; i < 20; i++) {
      read = await f.call({ operation: 'get', principalId, runId: ack.runId });
      if (read.state === 'COMPLETE') break;
      await new Promise<void>((r) => setImmediate(r));
    }
    expect(read).toMatchObject({
      state: 'COMPLETE',
      nativeThreadId: 'native-thread',
      outputMessageId: 'native-message',
      output: 'synthetic output',
    });
    const duplicate = await f.call(request);
    expect(duplicate.runId).toBe(ack.runId);
    expect(f.start).toHaveBeenCalledOnce();
    await expect(f.call({ ...request, partnerId: 'bot_other' })).rejects.toThrow();
    await expect(
      f.call({ operation: 'get', principalId: 'another', runId: ack.runId }),
    ).rejects.toThrow();
  } finally {
    f.sqlite.close();
  }
});
it('denies guessed partner, stale grant, permissions or profile changed while owner confirms', async () => {
  const f = fixture();
  try {
    await expect(f.call({ ...bind, partnerId: 'guessed' })).rejects.toThrow('UNAVAILABLE');
    f.confirm.mockImplementationOnce(async () => {
      f.approvalChange();
      return { approved: true, paths: [] };
    });
    await expect(f.call(bind)).rejects.toThrow('DENIED');
    expect(f.sqlite.prepare('SELECT count(*) n FROM plugin_task_requests').get()).toEqual({ n: 0 });
  } finally {
    f.sqlite.close();
  }
});
it('fence invalidates a reserved run before runner entry and preserves UNKNOWN', async () => {
  const f = fixture();
  try {
    await f.call(bind);
    await f.call({ operation: 'resume', principalId, expectedRevision: 1 });
    const ack = await f.call({
      operation: 'submit',
      principalId,
      partnerId: 'bot_real',
      grantRevision: 1,
      inputId: 'raced',
      text: 'Synthetic question',
    });
    f.profileChange();
    await f.call({ operation: 'fence', principalId, expectedRevision: 1 });
    await new Promise<void>((r) => setImmediate(r));
    const payloads = f.sqlite
      .prepare("SELECT payload FROM plugin_task_requests WHERE target_id LIKE 'restricted:input:%'")
      .all() as { payload: string }[];
    expect(payloads).toHaveLength(1);
    expect(JSON.parse(payloads[0]!.payload)).toMatchObject({ runId: ack.runId, state: 'UNKNOWN' });
    expect(f.start).not.toHaveBeenCalled();
  } finally {
    f.sqlite.close();
  }
});

it('capabilities require a current verified native runtime and never infer readiness from source presence', async () => {
  const f = fixture(false);
  try {
    expect(await f.call({ operation: 'capabilities' })).toMatchObject({
      execution: false,
      nativeVersionConfirmed: false,
    });
    await expect(f.call(bind)).rejects.toThrow('NATIVE_VERSION_UNVERIFIED');
    expect(f.confirm).not.toHaveBeenCalled();
    expect(f.start).not.toHaveBeenCalled();
  } finally {
    f.sqlite.close();
  }
});

it('binding reports current configured media permission; withdrawal cannot sign batch readiness', async () => {
  const f = fixture(true, { vision: { providerId: 'fake', modelId: 'vision' } });
  try {
    await f.call(bind);
    expect(await f.call({ operation: 'binding', principalId })).toMatchObject({
      media: { vision: true },
    });
    f.changeMedia({});
    expect(await f.call({ operation: 'binding', principalId })).toMatchObject({
      media: { vision: false },
      revision: 1,
      enabled: true,
    });
  } finally {
    f.sqlite.close();
  }
});

it('reviewed requirement revision/fingerprint is durable, incomplete actual tools cannot resume or submit; unknown schemas/principals refuse', async () => {
  const f = fixture();
  const requirement = {
    version: 1,
    revision: 1,
    principalId,
    addressHashes: ['a'.repeat(64)],
    source: { registry: 'b'.repeat(64), nativeConfig: 'c'.repeat(64), overlays: ['d'.repeat(64)] },
    tools: ['readonly-research', 'memory-read'],
    purposes: ['memory'],
    media: ['vision'],
  };
  try {
    const b = await f.call({ ...bind, requirements: requirement });
    expect(b.requirementsFingerprint).toBe(
      createHash('sha256').update(JSON.stringify(requirement)).digest('hex'),
    );
    const facts = await f.call({ operation: 'binding', principalId });
    expect(facts.missingRequirements).toContain('readonly-research');
    expect(facts.coverage.memory).toBe(0);
    await expect(f.call({ operation: 'resume', principalId, expectedRevision: 1 })).rejects.toThrow(
      'REQUIREMENTS_UNMET',
    );
    await expect(
      f.call({
        operation: 'submit',
        principalId,
        partnerId: bind.partnerId,
        grantRevision: 1,
        inputId: 'unsubmitted',
        text: 'synthetic',
      }),
    ).rejects.toThrow('REQUIREMENTS_UNMET');
    expect(f.start).not.toHaveBeenCalled();
    await expect(
      f.call({
        ...bind,
        expectedRevision: 1,
        requirements: { ...requirement, principalId: 'e'.repeat(64) },
      }),
    ).rejects.toThrow('INVALID_PARAMS');
    await expect(
      f.call({
        ...bind,
        expectedRevision: 1,
        requirements: { ...requirement, tools: ['arbitrary-shell'] },
      }),
    ).rejects.toThrow('REQUIREMENTS_INVALID');
    expect(f.confirm).toHaveBeenCalledTimes(1);
  } finally {
    f.sqlite.close();
  }
});

it('reviewed actual resource/namespace/model/media grant facts can be ready; model or media drift closes readiness without a run', async () => {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'grant-source-')));
  await mkdir(path.join(root, 'workspace'));
  await mkdir(path.join(root, 'notes'));
  const file = path.join(root, 'memory.db'),
    memory = new Database(file);
  memory.exec(
    "CREATE TABLE sticky_notes(namespace TEXT,note_key TEXT,content TEXT,updated_at INTEGER);INSERT INTO sticky_notes VALUES('mine','fact','preserved',1)",
  );
  memory.close();
  let modelId = 'fixture';
  const modelConfiguration = async () => ({ providerId: 'fixture-provider', modelId });
  const f = fixture(
    true,
    { vision: { providerId: 'vision', modelId: 'model' } },
    {
      research: true,
      modelConfiguration,
      prepare: async () => {
        throw Error('metadata test must not run a model');
      },
      confirm: async (req) => {
        req.assertCurrent();
        return {
          approved: true,
          paths: [],
          coverage: {
            workspace: [path.join(root, 'workspace')],
            notes: [path.join(root, 'notes')],
            memory: [file],
          },
          legacyNamespace: 'mine',
        };
      },
    },
  );
  const req = {
    version: 1,
    revision: 1,
    principalId,
    addressHashes: ['a'.repeat(64)],
    source: { registry: 'b'.repeat(64), nativeConfig: 'c'.repeat(64), overlays: ['d'.repeat(64)] },
    tools: [
      'channel-history',
      'native-code-analysis',
      'readonly-research',
      'workspace-read',
      'workspace-search',
      'notes-search',
      'memory-read',
      'memory-write',
    ],
    purposes: ['workspace', 'notes', 'memory'],
    media: ['vision'],
  };
  try {
    await f.call({ ...bind, requirements: req });
    const before = await f.call({ operation: 'binding', principalId });
    expect(before.missingRequirements).toEqual([]);
    expect(before.tools).toContain('partner_research');
    expect(before.coverage).toEqual({ workspace: 1, notes: 1, memory: 1 });
    expect(before.modelRoute.modelId).toBe('fixture');
    expect(before.media.vision).toBe(true);
    modelId = 'changed';
    expect((await f.call({ operation: 'binding', principalId })).missingRequirements).toContain(
      'model-route',
    );
    modelId = 'fixture';
    f.changeMedia({});
    expect((await f.call({ operation: 'binding', principalId })).missingRequirements).toContain(
      'vision',
    );
    expect(f.start).not.toHaveBeenCalled();
  } finally {
    f.sqlite.close();
    await rm(root, { recursive: true, force: true });
  }
});

import { originalMemoryFixture as originalSource, memoryHash } from './originalMemoryFixture.js';
import { mkdirSync, writeFileSync } from 'node:fs';
it('real binding approves proven original absence with durable facts; later source appearance blocks future model admission', async () => {
  const source = originalSource();
  const f = fixture(
    true,
    { vision: { providerId: 'vision', modelId: 'model' } },
    {
      modelConfiguration: async () => ({ providerId: 'fixture-provider', modelId: 'fixture' }),
      prepare: async () => {
        throw Error('metadata only');
      },
      confirm: async () => ({
        approved: true,
        paths: [],
        coverage: { memory: [source.root], 'durable-files': [source.durableRoot] },
        legacyNamespace: null,
        sourceRoots: {
          root: source.root,
          durableRoot: source.durableRoot,
          historicalAbsenceReviewed: true,
        },
      }),
    },
  );
  try {
    const requirement = source.requirements(principalId);
    const grant = await f.call({ ...bind, requirements: requirement });
    expect(grant.sourceInventoryFingerprint).toBe(memoryHash(JSON.stringify(source.inventory)));
    let facts = await f.call({ operation: 'binding', principalId });
    expect(facts.legacySourceState).toBe('absent');
    expect(facts.missingRequirements).toEqual([]);
    expect(facts.tools).toContain('partner_durable_memory');
    const resumed = await f.call({ operation: 'resume', principalId, expectedRevision: 1 });
    mkdirSync(path.dirname(source.database), { recursive: true });
    writeFileSync(source.database, 'LATE SOURCE');
    facts = await f.call({ operation: 'binding', principalId });
    expect(facts.legacySourceState).toBe('unavailable');
    expect(facts.missingRequirements).toContain('memory-source-changed');
    await expect(
      f.call({
        operation: 'submit',
        principalId,
        partnerId: 'bot_real',
        grantRevision: resumed.revision,
        inputId: 'new',
        text: 'synthetic',
        channel: { memoryRead: true },
      }),
    ).rejects.toThrow('REQUIREMENTS_UNMET');
    expect(f.start).not.toHaveBeenCalled();
  } finally {
    f.sqlite.close();
    source.cleanup();
  }
});
