import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { it, expect, vi } from 'vitest';
import { RESTRICTED_PARTNER, type AgentSessionHandle } from '@cindy/maker-core';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { tx } from '../../localDb/worker/opHandlers/tx.js';
import { ImageChannelRegistry } from '../../cindy-brain/imageChannelRegistry.js';
import {
  createRestrictedPartnerExecution,
  type RestrictedPartnerGrant,
} from '../restrictedPartnerExecution.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import {
  restrictedConversation,
  assertOrdinaryPartnerLane,
} from '../restrictedPartnerConversation.js';
import { restrictedPartnerMedia } from '../restrictedPartnerMedia.js';
const mocks = vi.hoisted(() => ({
  images: null as unknown,
  vision: undefined as any,
  routes: {} as Record<string, unknown>,
  ingest: vi.fn(),
  network: vi.fn(),
}));
vi.mock('../../maker-host/outbound-fetch.js', () => ({
  outboundFetch: () => {
    throw Error('UNSCOPED_TEST_NETWORK_DENIED');
  },
  guardedOutboundFetch: async (url: any, init: any, current: any) => {
    current();
    const response = await mocks.network(url, init);
    current();
    return { response, release: async () => {} };
  },
}));
vi.mock('../../cindy-brain/index.js', () => ({
  restrictedPartnerImageConfiguration: () => ({ images: mocks.images, routes: mocks.routes }),
  getGhostLibrarySlot: () => ({
    importStream: async () => ({ ok: true }),
    resolvePanelFilePath: async (_plugin: string, rel: string) => '/managed/' + rel,
  }),
}));
vi.mock('../../maker-host/index.js', () => ({
  restrictedPartnerVisionConfiguration: async () => mocks.vision,
}));
vi.mock('../../voice-input/index.js', () => ({
  restrictedPartnerTranscriptionConfiguration: () => undefined,
}));
vi.mock('../../voice-conversation/index.js', () => ({
  restrictedPartnerSpeechConfiguration: async () => undefined,
}));
vi.mock('../../cindy-media/ingest.js', () => ({
  ingestMedia: (...args: unknown[]) => mocks.ingest(...args),
}));
vi.mock('../../cindy-media/refCompensationJournal.js', () => ({
  captureMediaRefCompensationScope: () => ({ ownerStorageKey: 'synthetic' }),
}));
const sha = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex');
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWoQAAAAASUVORK5CYII=',
  'base64',
);
function fixture() {
  mocks.ingest.mockClear();
  mocks.vision = undefined;
  const sql = new Database(':memory:');
  sql.exec(`
      CREATE TABLE sessions (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, working_dir TEXT, project_dir TEXT, workspace_kind TEXT NOT NULL,
        model TEXT NOT NULL, effort TEXT NOT NULL, permission_mode TEXT NOT NULL, status TEXT NOT NULL,
        scheduled_model_baseline TEXT,
        sdk_session_id TEXT, total_token_usage INTEGER NOT NULL, total_cost_usd REAL NOT NULL,
        context_tokens INTEGER NOT NULL, context_window INTEGER NOT NULL, fast_mode INTEGER NOT NULL,
        plan_mode_enabled INTEGER NOT NULL, cleared_at INTEGER, pinned_at INTEGER, user_send_at INTEGER,
        agent_kind TEXT NOT NULL, orca_role TEXT, parent_session_id TEXT, forked_at_message_id TEXT,
        worktree_path TEXT, extra_dirs TEXT NOT NULL, remote_host_id TEXT, provider_id TEXT, agent_device_id TEXT,
        source TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
      );
      CREATE TABLE bot_profiles (
        id TEXT PRIMARY KEY, display_name TEXT NOT NULL, description TEXT NOT NULL, avatar TEXT NOT NULL,
        avatar_color TEXT NOT NULL, status TEXT NOT NULL, current_version INTEGER NOT NULL,
        hidden_at INTEGER, pinned_at INTEGER, attention_reason TEXT, attention_at INTEGER,
        canonical_session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
      );
      CREATE TABLE bot_profile_versions (
        id TEXT PRIMARY KEY, bot_id TEXT NOT NULL REFERENCES bot_profiles(id) ON DELETE CASCADE,
        version INTEGER NOT NULL, identity_source TEXT NOT NULL, capabilities_json TEXT NOT NULL,
        created_at INTEGER NOT NULL, UNIQUE(bot_id, version)
      );
      CREATE TABLE bot_session_links (
        id TEXT PRIMARY KEY, bot_id TEXT NOT NULL REFERENCES bot_profiles(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
        profile_version INTEGER NOT NULL, role TEXT NOT NULL, route_key TEXT,
        created_at INTEGER NOT NULL, archived_at INTEGER
      );
      CREATE UNIQUE INDEX uniq_bot_canonical ON bot_session_links(bot_id) WHERE role = 'canonical';
      CREATE TABLE bot_lifecycle_events (
        id TEXT PRIMARY KEY, bot_id TEXT NOT NULL REFERENCES bot_profiles(id) ON DELETE CASCADE,
        session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL, event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL, created_at INTEGER NOT NULL
      );

 CREATE TABLE messages(id TEXT PRIMARY KEY,client_id TEXT,session_id TEXT,role TEXT,content TEXT,tool_use_id TEXT,agent_meta TEXT,agent_kind TEXT,created_at INTEGER,rewind_at INTEGER,UNIQUE(session_id,client_id));
 CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key));
 INSERT INTO bot_profiles(id,display_name,description,avatar,avatar_color,status,current_version,created_at,updated_at)VALUES('bot','Synthetic','','','blue','active',1,1,1);
 INSERT INTO bot_profile_versions(id,bot_id,version,identity_source,capabilities_json,created_at)VALUES('v','bot',1,'Approved persona','{"permissions":"ask"}',1);
 `);
  const db = {
    drizzle: drizzle(sql),
    exec: async (s: string, a: unknown[]) => ({ changes: sql.prepare(s).run(...a).changes }),
    tx: async (name: string, args: unknown) => tx(sql, { name, args } as never),
  } as unknown as DbClient;
  let active = true;
  const current = () => {
    if (!active) throw Error('REVOKED');
  };
  const store = createRestrictedPartnerStore(db, current);
  const grant: RestrictedPartnerGrant = {
    version: 1,
    id: 'grant',
    pluginId: 'plugin',
    partnerId: 'bot',
    principalId: sha(JSON.stringify(['domain', 'person'])),
    revision: 1,
    enabled: true,
    personaSha256: sha('Approved persona'),
    resourceIds: [],
    resources: [],
    approvalRevision: 'a',
    dispatchEpoch: 1,
    dispatchEnabled: true,
    media: { draw: { providerId: 'fake', modelId: 'draw' } },
  };
  const route = {
    workingDir: '/synthetic',
    providerId: 'fake',
    model: 'text',
    effort: 'medium' as const,
  };
  const channel = {
    domainId: 'domain',
    principalId: 'person',
    connectionId: 'c',
    generation: 'g',
    chatId: 'original',
    memoryRead: true,
    eventId: 'new',
    revision: 1,
    epoch: 1,
  };
  return {
    sql,
    db,
    current,
    store,
    grant,
    route,
    channel,
    revoke: () => {
      active = false;
    },
  };
}
it('real Main receipt + real Bot lane transaction + scoped memory/history and Core media tools, exact output once', async () => {
  const f = fixture();
  let models = 0,
    paid = 0;
  const registry = new ImageChannelRegistry();
  registry.register('fake', {
    ready: () => true,
    generateImage: async () => {
      paid++;
      return { data: [{ b64_json: png.toString('base64') }] };
    },
    editImage: async () => {
      throw Error('not-used');
    },
  });
  mocks.images = registry;
  mocks.routes = { draw: f.grant.media!.draw };
  mocks.ingest.mockImplementation(async (p: any, db: any) => {
    expect(db).toBe(f.db.drizzle);
    p.assertStillValid();
    expect(p.refs[0].refId).toMatch(/^restricted:/);
    return {
      hash: sha(p.buffer),
      ext: '.png',
      mimeType: p.mimeType,
      bytes: p.buffer.length,
      refIds: [],
      url: 'cindy-media://synthetic',
    };
  });
  await f.store.compareAndSwapGrant(f.grant, 0);
  let append: any;
  let tools: any[] = [];
  const service = createRestrictedPartnerExecution({
    ...f.store,
    assertCurrent: f.current,
    readGrant: () => f.store.readGrant('plugin', 'grant'),
    route: async () => f.route,
    project: async () => ({ persona: 'Approved persona', subjectContext: '', readPaths: [] }),
    prepare: async (g, cl, route, current, assets) => {
      const conversation = await restrictedConversation(f.db, g, cl, route, current);
      const media = await restrictedPartnerMedia(f.db, g, cl, current, assets);
      append = conversation.append;
      return {
        context: conversation.context + media.context,
        tools: [...conversation.tools, ...media.tools],
        laneSessionId: conversation.laneSessionId,
        outputs: media.outputs,
      };
    },
    afterComplete: async (cl, text) => append(cl, text, f.current),
    start: async (opts) => {
      models++;
      tools = [...opts[RESTRICTED_PARTNER]!.tools];
      let ready!: () => void;
      const done = new Promise<void>((r) => {
        ready = r;
      });
      return {
        id: 'native-thread',
        close: async () => {},
        send: async () => {
          const memory = tools.find((t) => t.name === 'partner_memory');
          await memory.invoke(
            { facts: ['only this subject'], expectedRevision: 0 },
            { runId: opts.sessionId, callId: 'memory' },
          );
          await expect(
            memory.invoke(
              { facts: ['stale'], expectedRevision: 0 },
              { runId: opts.sessionId, callId: 'stale' },
            ),
          ).rejects.toThrow('TOOL_UNCONFIRMED');
          await expect(
            memory.invoke('SYNTHETIC_PRIVATE_BAD_JSON', {
              runId: opts.sessionId,
              callId: 'invalid',
            }),
          ).rejects.toThrow('TOOL_UNCONFIRMED');
          const media = tools.find((t) => t.name === 'partner_media');
          const a = await media.invoke(
            { kind: 'draw', text: 'synthetic square' },
            { runId: opts.sessionId, callId: 'draw' },
          );
          expect(a.success).toBe(true);
          await media.invoke(
            { kind: 'draw', text: 'synthetic square' },
            { runId: opts.sessionId, callId: 'duplicate' },
          );
          ready();
        },
        async *events() {
          await done;
          yield {
            type: 'text',
            data: {
              text: 'Complete original answer',
              agentMessageId: 'native-output',
              phase: 'final',
            },
          };
          yield { type: 'done', data: {} };
        },
      } as unknown as AgentSessionHandle;
    },
  });
  const request = {
    grantId: 'grant',
    pluginId: 'plugin',
    principalId: f.grant.principalId,
    partnerId: 'bot',
    inputId: 'input',
    text: JSON.stringify({ question: 'new question', facts: ['injected memory'], documents: [] }),
    channel: f.channel,
  };
  try {
    const result = await service.run(request);
    expect(result.state).toBe('COMPLETE');
    expect(result.assets).toHaveLength(1);
    expect(result.assets![0].binding.chatId).toBe('original');
    expect(paid).toBe(1);
    expect(models).toBe(1);
    expect(await f.store.unresolvedCount('plugin', f.grant.principalId)).toBe(0);
    await service.run(request);
    expect(paid).toBe(1);
    expect(models).toBe(1);
    expect(f.sql.prepare('SELECT count(*) n FROM messages').get()).toEqual({ n: 2 });
    expect(
      JSON.parse(
        (
          f.sql.prepare("SELECT content FROM messages WHERE role='user'").get() as {
            content: string;
          }
        ).content,
      ),
    ).toEqual([{ type: 'text', text: 'new question' }]);
    expect(f.sql.prepare('SELECT role,route_key FROM bot_session_links').get()).toMatchObject({
      role: 'channel',
      route_key: expect.stringMatching(/^im:restricted:/),
    });
    await expect(assertOrdinaryPartnerLane(f.db, result.laneSessionId!)).rejects.toThrow(
      'READ_ONLY',
    );
    await assertOrdinaryPartnerLane(f.db, 'ordinary');
    const next = await restrictedConversation(
      f.db,
      f.grant,
      { ...result, runId: 'next', inputId: 'next', channel: { ...f.channel, eventId: 'next' } },
      f.route,
      f.current,
    );
    expect(next.context).toContain('new question');
    expect(next.context).toContain('Complete original answer');
    const other = await restrictedConversation(
      f.db,
      { ...f.grant, principalId: sha(JSON.stringify(['domain', 'other'])) },
      { ...result, runId: 'other', channel: { ...f.channel, principalId: 'other' } },
      f.route,
      f.current,
    );
    expect(other.context).not.toContain('Complete original answer');
    const read = await other.tools
      .find((x) => x.name === 'partner_memory')!
      .invoke({}, { callId: 'read', runId: 'other' });
    expect(JSON.stringify(read)).not.toContain('only this subject');
    f.revoke();
    await expect(next.tools[0]!.invoke({}, { runId: 'next', callId: 'revoked' })).rejects.toThrow(
      'REVOKED',
    );
  } finally {
    f.sql.close();
  }
});
it('late revoked media output preserves original UNKNOWN effect and never attaches output', async () => {
  const f = fixture();
  const registry = new ImageChannelRegistry();
  let paid = 0;
  registry.register('fake', {
    ready: () => true,
    generateImage: async () => {
      paid++;
      f.revoke();
      return { data: [{ b64_json: png.toString('base64') }] };
    },
    editImage: async () => {
      throw Error('not-used');
    },
  });
  mocks.images = registry;
  mocks.routes = { draw: f.grant.media!.draw };
  const claim = {
    version: 1 as const,
    runId: 'run',
    inputId: 'input',
    pluginId: 'plugin',
    principalId: f.grant.principalId,
    partnerId: 'bot',
    grantId: 'grant',
    grantRevision: 1,
    inputSha256: 'a'.repeat(64),
    state: 'UNKNOWN' as const,
    channel: f.channel,
  };
  try {
    const media = await restrictedPartnerMedia(f.db, f.grant, claim, f.current, []);
    await expect(
      media.tools[0]!.invoke(
        { kind: 'draw', text: 'synthetic' },
        { runId: 'run', callId: 'effect' },
      ),
    ).rejects.toThrow();
    expect(paid).toBe(1);
    const row = f.sql
      .prepare(
        "SELECT payload FROM plugin_task_requests WHERE target_id LIKE 'restricted:effect:%'",
      )
      .get() as { payload: string };
    expect(JSON.parse(row.payload).state).toBe('UNKNOWN');
    expect(mocks.ingest).not.toHaveBeenCalled();
  } finally {
    f.sql.close();
  }
});
it('missing/mismatched original scope cannot create a canonical lane or private history', async () => {
  const f = fixture();
  try {
    const claim = {
      version: 1 as const,
      runId: 'run',
      inputId: 'i',
      pluginId: 'plugin',
      principalId: f.grant.principalId,
      partnerId: 'bot',
      grantId: 'grant',
      grantRevision: 1,
      inputSha256: 'a'.repeat(64),
      state: 'UNKNOWN' as const,
    };
    await expect(restrictedConversation(f.db, f.grant, claim, f.route, f.current)).rejects.toThrow(
      'DENIED',
    );
    expect(f.sql.prepare('SELECT count(*) n FROM bot_session_links').get()).toEqual({ n: 0 });
  } finally {
    f.sql.close();
  }
});

it('exact input/edit pixels and distinct sequential/concurrent effects retain independent provenance and never recharge the same effect', async () => {
  const f = fixture();
  let paid = 0;
  const registry = new ImageChannelRegistry();
  registry.register('fake', {
    ready: () => true,
    generateImage: async () => {
      paid++;
      return { data: [{ b64_json: png.toString('base64') }] };
    },
    editImage: async () => {
      paid++;
      return { data: [{ b64_json: png.toString('base64') }] };
    },
  });
  f.grant.media = {
    draw: { providerId: 'fake', modelId: 'draw' },
    edit: { providerId: 'fake', modelId: 'edit' },
    vision: { providerId: 'fake', modelId: 'vision' },
  };
  mocks.images = registry;
  mocks.routes = { draw: f.grant.media.draw, edit: f.grant.media.edit };
  mocks.vision = { route: f.grant.media.vision, deps: {}, assertCurrent: f.current };
  mocks.ingest.mockImplementation(async (p: any) => {
    p.assertStillValid();
    return { ext: '.png' };
  });
  const claim = {
    version: 1,
    runId: 'same-pixels',
    inputId: 'new',
    pluginId: 'plugin',
    principalId: f.grant.principalId,
    partnerId: 'bot',
    grantId: 'grant',
    grantRevision: 1,
    inputSha256: sha('question'),
    state: 'UNKNOWN',
    channel: f.channel,
  } as const;
  try {
    const media = await restrictedPartnerMedia(f.db, f.grant, claim as any, f.current, [
      {
        id: 'asset:' + sha(png),
        sha256: sha(png),
        mimeType: 'image/png',
        base64: png.toString('base64'),
        sourceSha256: sha(png),
        partial: false,
      },
    ]);
    const input = JSON.parse(media.context).authorizedRequestMedia[0].id,
      tool = media.tools[0]!;
    const invoke = (text: string, kind = 'draw', inputId?: string) =>
      tool.invoke(
        { kind, text, ...(inputId ? { inputId } : {}) },
        { callId: text, runId: claim.runId },
      );
    await invoke('edit same pixels', 'edit', input);
    await Promise.all([invoke('draw first'), invoke('draw second')]);
    expect(paid).toBe(3);
    const outputs = media.outputs();
    expect(outputs).toHaveLength(3);
    expect(new Set(outputs.map((a) => a.id)).size).toBe(3);
    expect(new Set(outputs.map((a) => a.sha256)).size).toBe(1);
    const saved = f.sql
      .prepare("SELECT payload FROM plugin_task_requests WHERE target_id LIKE 'restricted:asset:%'")
      .all() as Array<{ payload: string }>;
    expect(saved).toHaveLength(4);
    for (const out of outputs)
      expect(
        saved.some((r) => {
          const b = JSON.parse(r.payload).binding;
          return (
            Object.keys(b).length === Object.keys(out.binding).length &&
            Object.entries(out.binding).every(([k, v]) => b[k] === v)
          );
        }),
      ).toBe(true);
    await invoke('draw first');
    expect(paid).toBe(3);
    expect(media.outputs()).toHaveLength(3);
    await expect(invoke('bad scope', 'edit', 'asset:' + sha('other'))).rejects.toThrow();
    expect(paid).toBe(3);
  } finally {
    f.sql.close();
  }
});

import { originalMemoryFixture } from './originalMemoryFixture.js';
import { assertMemorySources } from '../restrictedPartnerLegacyMemory.js';
import { existsSync } from 'node:fs';
it('real per-subject memory CAS still saves new facts when approved old DB never existed; alias shares facts, other subject cannot read them', async () => {
  const f = fixture(),
    source = originalMemoryFixture();
  try {
    const g = { ...f.grant, memorySources: source.approve() };
    const current = () => {
      f.current();
      assertMemorySources(g.memorySources, f.current);
    };
    const claim = {
      version:1 as const,runId:'new-memory-run',inputId:'new-memory-input',pluginId:g.pluginId,principalId:g.principalId,partnerId:g.partnerId,grantId:g.id,grantRevision:g.revision,inputSha256:sha('synthetic new question'),state:'UNKNOWN' as const,
      text:'synthetic new question',
      channel: f.channel,
    } as Parameters<typeof restrictedConversation>[2];
    const lane = await restrictedConversation(f.db, g, claim, f.route, current);
    const memory = lane.tools.find((t) => t.name === 'partner_memory')!;
    await memory.invoke(
      { facts: ['NEW_SUBJECT_FACT'], expectedRevision: 0 },
      { callId: 'save', runId: claim.runId },
    );
    expect(existsSync(source.database)).toBe(false);
    const alias = await restrictedConversation(
      f.db,
      g,
      { ...claim, channel: { ...f.channel, chatId: 'same-person-alias' } },
      f.route,
      current,
    );
    expect(
      JSON.stringify(
        await alias.tools
          .find((t) => t.name === 'partner_memory')!
          .invoke({}, { callId: 'read', runId: claim.runId }),
      ),
    ).toContain('NEW_SUBJECT_FACT');
    const other = { ...g, principalId: sha(JSON.stringify(['domain', 'other'])) };
    const foreign = await restrictedConversation(
      f.db,
      other,
      { ...claim, channel: { ...f.channel, principalId: 'other' } },
      f.route,
      current,
    );
    expect(
      JSON.stringify(
        await foreign.tools
          .find((t) => t.name === 'partner_memory')!
          .invoke({}, { callId: 'read', runId: claim.runId }),
      ),
    ).not.toContain('NEW_SUBJECT_FACT');
  } finally {
    f.sql.close();
    source.cleanup();
  }
});

it('actual Main video input stage/SQL/Core tool claims one bounded window, keeps PTS and rejects packet drift/revocation', async () => {
  const f = fixture();
  f.grant.media = { vision: { providerId: 'fake', modelId: 'vision' } };
  mocks.routes = {};
  mocks.images = new ImageChannelRegistry();
  mocks.vision = {
    route: f.grant.media.vision,
    assertCurrent: f.current,
    deps: {
      getProviderById: () => null,
      resolveBackendRoute: () => ({
        upstream: 'https://fixture.invalid/v1',
        requestPath: '/chat/completions',
        model: 'vision',
        authorization: null,
        headers: {},
        wireProtocol: 'openai-chat',
      }),
    },
  };
  mocks.network.mockReset();
  mocks.network.mockImplementation(async () =>
    Response.json({ choices: [{ message: { content: 'One bounded frame' } }] }),
  );
  mocks.ingest.mockImplementation(async (p: any) => {
    p.assertStillValid();
    return { ext: '.png' };
  });
  const { grantResourceFingerprint } = await import('../restrictedPartnerRequirements.js');
  const claim: any = {
    version: 1,
    runId: 'video-run',
    inputId: 'video-input',
    pluginId: 'plugin',
    principalId: f.grant.principalId,
    partnerId: 'bot',
    grantId: 'grant',
    grantRevision: 1,
    inputSha256: sha('question'),
    state: 'UNKNOWN',
    channel: f.channel,
  };
  const sourceSha256 = sha('original video');
  const binding = {
    ...f.channel,
    principalId: f.grant.principalId,
    partnerId: 'bot',
    runId: 'input:' + claim.inputId,
    resourceFingerprint: grantResourceFingerprint(f.grant),
    providerId: 'fake',
    modelId: 'vision',
    effectSlot: 'prepare-video:' + sourceSha256,
  };
  delete (binding as any).memoryRead;
  const video: any = {
    binding,
    sourceId: 'asset:' + sourceSha256,
    sourceSha256,
    durationSeconds: 2,
    startSeconds: 0,
    windowSeconds: 2,
    timeBasis: 'decoder-presentation-timestamp',
    partial: true,
    sampling: 'at-most-three-seeks-one-second-apart',
    frames: [0, 1].map((index) => ({
      index,
      timestampSeconds: index + 0.05,
      requestedSeconds: index,
      base64: png.toString('base64'),
      sha256: sha(png),
      mimeType: 'image/png',
    })),
  };
  const input: any = {
    type: 'video',
    id: 'video:' + sha(JSON.stringify(video)),
    sourceSha256,
    video,
  };
  try {
    await expect(
      restrictedPartnerMedia(f.db, f.grant, claim, f.current, [
        { ...input, video: { ...video, binding: { ...binding, chatId: 'other' } } },
      ]),
    ).rejects.toThrow('DENIED');
    expect(mocks.network).not.toHaveBeenCalled();
    const media = await restrictedPartnerMedia(f.db, f.grant, claim, f.current, [input]);
    const tool = media.tools.find((t) => t.name === 'partner_video')!;
    await expect(
      tool.invoke(
        { sourceId: 'forged', text: 'describe' },
        { runId: claim.runId, callId: 'wrong' },
      ),
    ).rejects.toThrow('DENIED');
    const result: any = await tool.invoke(
      { sourceId: video.sourceId, text: 'describe' },
      { runId: claim.runId, callId: 'ok' },
    );
    expect(result.success).toBe(true);
    expect(JSON.stringify(result)).toContain('0.05');
    expect(mocks.network).toHaveBeenCalledTimes(2);
    await tool.invoke(
      { sourceId: video.sourceId, text: 'describe' },
      { runId: claim.runId, callId: 'duplicate' },
    );
    expect(mocks.network).toHaveBeenCalledTimes(2);
    expect(media.outputs()).toEqual([]);
    f.revoke();
    await expect(
      tool.invoke(
        { sourceId: video.sourceId, text: 'different' },
        { runId: claim.runId, callId: 'revoke' },
      ),
    ).rejects.toThrow('REVOKED');
    expect(mocks.network).toHaveBeenCalledTimes(2);
    expect(
      f.sql
        .prepare(
          "SELECT count(*) n FROM plugin_task_requests WHERE target_id LIKE 'restricted:video:%'",
        )
        .get(),
    ).toEqual({ n: 1 });
  } finally {
    f.sql.close();
  }
});
it('actual Main URL-result stage requires exact approval before one bounded download and keeps UNKNOWN after revoked approval', async () => {
  const f = fixture();
  mocks.vision = undefined;
  const registry = new ImageChannelRegistry();
  let paid = 0,
    approved = false;
  registry.register('fake', {
    ready: () => true,
    generateImage: async () => {
      paid++;
      return { data: [{ url: 'https://cdn.example.invalid/generated.png' }] };
    },
    editImage: async () => {
      throw Error('unused');
    },
  });
  mocks.images = registry;
  mocks.routes = { draw: f.grant.media!.draw };
  mocks.network.mockReset();
  mocks.network.mockImplementation(
    async () => new Response(png, { headers: { 'content-type': 'image/png' } }),
  );
  mocks.ingest.mockImplementation(async (p: any) => {
    p.assertStillValid();
    return { ext: '.png' };
  });
  const claim: any = {
    version: 1,
    runId: 'url-run',
    inputId: 'url-input',
    pluginId: 'plugin',
    principalId: f.grant.principalId,
    partnerId: 'bot',
    grantId: 'grant',
    grantRevision: 1,
    inputSha256: sha('question'),
    state: 'UNKNOWN',
    channel: f.channel,
  };
  const approval = {
    approve: async () => {
      approved = true;
    },
    authorize: (p: any, url: string, role: any) => {
      f.current();
      if (!approved) throw Error('DENIED');
      return {
        binding: p.binding,
        role,
        sourceSha256: sha(url),
        hosts: ['cdn.example.invalid'],
        revision: 1,
      };
    },
    assertCurrent: () => f.current(),
  };
  try {
    const media = await restrictedPartnerMedia(
      f.db,
      f.grant,
      claim,
      f.current,
      [],
      undefined,
      approval,
    );
    await media.tools[0]!.invoke(
      { kind: 'draw', text: 'synthetic' },
      { runId: claim.runId, callId: 'draw' },
    );
    expect(paid).toBe(1);
    expect(approved).toBe(true);
    expect(mocks.network).toHaveBeenCalledOnce();
    expect(media.outputs()).toHaveLength(1);
    const held = await restrictedPartnerMedia(
      f.db,
      f.grant,
      { ...claim, runId: 'late-url' },
      f.current,
      [],
      undefined,
      {
        ...approval,
        approve: async () => {
          f.revoke();
        },
      },
    );
    await expect(
      held.tools[0]!.invoke({ kind: 'draw', text: 'late' }, { runId: 'late-url', callId: 'late' }),
    ).rejects.toThrow();
    expect(paid).toBe(2);
    expect(mocks.network).toHaveBeenCalledOnce();
  } finally {
    f.sql.close();
  }
});
