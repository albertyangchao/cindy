import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { DbClient } from '../../localDb/client/DbClient.js';
import { tx } from '../../localDb/worker/opHandlers/tx.js';
import { createRestrictedPartnerHost } from '../restrictedPartnerHost.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { restrictedConversation } from '../restrictedPartnerConversation.js';
import type { RestrictedChannelInput, RestrictedPartnerClaim, RestrictedPartnerGrant } from '../restrictedPartnerExecution.js';
import type { RestrictedPartnerMigrationSnapshot } from '../restrictedPartnerLegacyMemory.js';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
/** Real SQLite, real grant store/Host entry, and the production Bot-lane transaction. */
export async function migrationFixture() {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'restricted-migration-')));
  const sqlite = new Database(':memory:');
  sqlite.exec(`
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, working_dir TEXT, project_dir TEXT, workspace_kind TEXT NOT NULL,
      model TEXT NOT NULL, effort TEXT NOT NULL, permission_mode TEXT NOT NULL, status TEXT NOT NULL,
      scheduled_model_baseline TEXT, sdk_session_id TEXT, total_token_usage INTEGER NOT NULL, total_cost_usd REAL NOT NULL,
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
    CREATE TABLE messages(id TEXT PRIMARY KEY,client_id TEXT,session_id TEXT,role TEXT,content TEXT,
      tool_use_id TEXT,agent_meta TEXT,agent_kind TEXT,created_at INTEGER,rewind_at INTEGER,UNIQUE(session_id,client_id));
    CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,
      request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,
      UNIQUE(plugin_id,operation,target_id,request_key));
    INSERT INTO bot_profiles(id,display_name,description,avatar,avatar_color,status,current_version,created_at,updated_at)
      VALUES('bot_real','Synthetic native partner','','','blue','active',1,1,1);
    INSERT INTO bot_profile_versions(id,bot_id,version,identity_source,capabilities_json,created_at)
      VALUES('v','bot_real',1,'Approved persona','{"permissions":"ask"}',1);
  `);
  let active = true, effectCalls = 0, beforeQuery: (() => void | Promise<void>) | undefined;
  const current = () => { if (!active) throw Error('REVOKED'); };
  const db = {
    drizzle: drizzle(sqlite),
    exec: async (statement: string, values: unknown[] = []) => ({ changes: sqlite.prepare(statement).run(...values).changes }),
    query: async (statement: string, values: unknown[] = []) => {
      const hook = beforeQuery;
      beforeQuery = undefined;
      await hook?.();
      return sqlite.prepare(statement).all(...values);
    },
    tx: async (name: string, args: unknown) => tx(sqlite, { name, args }),
  } as unknown as DbClient;
  const store = createRestrictedPartnerStore(db, current);
  let selectedPaths = [root];
  const route = { model: 'fixture', providerId: 'fixture-provider', workingDir: root, effort: 'medium' as const };
  const host = createRestrictedPartnerHost({
    executionReady: async () => true,
    snapshot: () => ({ client: db, assertCurrent: current }),
    approvalRevision: () => 'synthetic-owner-approval',
    candidates: async () => [{ id: 'bot_real', label: 'Synthetic native partner', detail: '' }],
    partner: async () => ({ persona: 'Approved persona', version: 1 }),
    partnerAuthority: () => current,
    route: async () => route,
    start: async () => { effectCalls++; throw Error('UNEXPECTED_MODEL_EFFECT'); },
    confirm: async () => ({ approved: true, paths: selectedPaths }),
  });
  const scope = { domainId: 'family', principalId: 'subject_A' };
  const principalId = sha(JSON.stringify([scope.domainId, scope.principalId]));
  const call = (request: unknown) => host('plugin', request, current) as Promise<any>;
  const bound = await call({ operation: 'bind', principalId, partnerId: 'bot_real', expectedRevision: 0 });
  let grant = (await store.readGrant('plugin', bound.grantId))!;
  const channel: RestrictedChannelInput = { ...scope, connectionId: 'connection_A', generation: 'generation_1',
    chatId: 'original_chat_A', eventId: 'event_new', revision: 1, epoch: 1, memoryRead: true };
  const snapshot: RestrictedPartnerMigrationSnapshot = { version: 1, ...scope, sourceId: 'original_subject_export', records: [
    { ...scope, sourceKey: 'turn:1', kind: 'history', chatId: channel.chatId, state: 'COMPLETE', question: 'Earlier question', answer: 'Earlier answer' },
    { ...scope, sourceKey: 'turn:unknown', kind: 'history', chatId: channel.chatId, state: 'UNKNOWN', question: 'Never replay this' },
    { ...scope, sourceKey: 'facts:1', kind: 'facts', facts: ['Approved subject fact'] },
    { ...scope, sourceKey: 'document:1', kind: 'document', resourceId: 'reference_A', nativeResourceId: grant.resourceIds[0]!, text: 'Approved subject document' },
  ] };
  const claim = (changes: Partial<RestrictedChannelInput> = {}): RestrictedPartnerClaim => ({
    version: 1, runId: 'read-only-context', inputId: 'context', pluginId: grant.pluginId,
    principalId: grant.principalId, partnerId: grant.partnerId, grantId: grant.id, grantRevision: grant.revision,
    inputSha256: sha('new question'), state: 'UNKNOWN', inputText: 'new question', channel: { ...channel, ...changes },
  });
  return {
    sqlite, db, root, current, store, route, scope, channel, snapshot, principalId, call, claim,
    get grant() { return grant; },
    get effectCalls() { return effectCalls; },
    rows: () => sqlite.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all(),
    imports: () => sqlite.prepare("SELECT * FROM plugin_task_requests WHERE target_id LIKE 'restricted:migration:%' ORDER BY id").all(),
    migrate: (mode: 'dry-run' | 'apply', value: unknown = snapshot) => call({ operation: 'migration', principalId,
      partnerId: grant.partnerId, expectedRevision: grant.revision, mode, snapshot: value }),
    conversation: (changes: Partial<RestrictedChannelInput> = {}, scopedGrant: RestrictedPartnerGrant = grant) =>
      restrictedConversation(db, scopedGrant, claim(changes), route, current),
    async rebind(paths: string[] = selectedPaths) {
      selectedPaths = paths;
      await call({ operation: 'bind', principalId, partnerId: grant.partnerId, expectedRevision: grant.revision });
      grant = (await store.readGrant('plugin', grant.id))!;
      return grant;
    },
    beforeWrite: (hook: () => void | Promise<void>) => { beforeQuery = hook; },
    revoke: () => { active = false; },
    close: async () => { sqlite.close(); await rm(root, { recursive: true, force: true }); },
  };
}

export async function migrationTool(conversation: Awaited<ReturnType<typeof restrictedConversation>>, name: string, args: unknown) {
  const tool = conversation.tools.find((entry) => entry.name === name);
  if (!tool) throw Error('MISSING_EXPECTED_TOOL');
  const result = await tool.invoke(args, { callId: 'synthetic-read', runId: 'read-only-context' });
  if (!result.success) throw Error('EXPECTED_SCOPED_READ');
  const text = result.contentItems.find((item) => item.type === 'inputText');
  if (!text || text.type !== 'inputText') throw Error('EXPECTED_TEXT');
  return { value: JSON.parse(text.text), text: text.text };
}
