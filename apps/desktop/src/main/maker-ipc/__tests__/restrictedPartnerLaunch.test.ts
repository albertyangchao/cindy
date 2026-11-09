import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { expect, it, vi } from 'vitest';
import type { DbClient } from '../../localDb/client/DbClient.js';
import type { RestrictedChannelInput, RestrictedPartnerClaim } from '../restrictedPartnerExecution.js';
import { createRestrictedPartnerHost, type RestrictedPartnerHostDeps } from '../restrictedPartnerHost.js';
import { holdRestrictedPartnerLaunch } from '../restrictedPartnerLaunch.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { originalMemoryFixture } from './originalMemoryFixture.js';

// Integration tier, real SQLite and the public Host producer/consumer. The
// minimal regression is excluding an UNKNOWN from admission without an exact,
// private Host hold. Generic Host control tests do not exercise this protocol.
// The runner is a synthetic boundary failure, never a platform/readiness proof.
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const pluginId = 'synthetic_plugin';
const partnerId = 'bot_real';
const localPrincipalId = 'subject_A';
const principalId = hash(['family', localPrincipalId]);
type Route = {
  domainId: string; principalId: string; connectionId: string; generation: string;
  addressHash: string; inputs: Array<{ inputId: string; eventId: string; chatId: string }>;
};
type Snapshot = {
  version: number; snapshotId: string; sha256: string; unresolvedCount: number;
  records: Array<{ inputId: string; runId: string; routeHash: string; eventId: string; chatId: string }>;
};

async function fixture() {
  const source = originalMemoryFixture();
  const sqlite = new Database(':memory:');
  sqlite.exec(`CREATE TABLE plugin_task_requests (
    id TEXT PRIMARY KEY, plugin_id TEXT, operation TEXT, target_id TEXT,
    request_key TEXT, fingerprint TEXT, payload TEXT, revision INTEGER, created_at INTEGER,
    UNIQUE(plugin_id,operation,target_id,request_key));`);
  const db = {
    drizzle: drizzle(sqlite),
    exec: async (sql: string, params: unknown[]) => ({ changes: sqlite.prepare(sql).run(...params).changes }),
  } as unknown as DbClient;
  let mediaReady = true;
  const guard = () => {};
  const start = vi.fn(async () => { throw Error('SYNTHETIC_RUNNER_ACK_UNKNOWN'); });
  const deps: RestrictedPartnerHostDeps = {
    snapshot: () => ({ client: db, assertCurrent: guard }),
    approvalRevision: () => 'approved-synthetic-install',
    executionReady: async () => true,
    candidates: async () => [{ id: partnerId, label: 'Synthetic existing partner', detail: '' }],
    partnerAuthority: () => guard,
    partner: async () => ({ persona: 'Approved synthetic persona', version: 1 }),
    modelConfiguration: async () => ({ providerId: 'fixture-provider', modelId: 'fixture-model' }),
    mediaConfiguration: async () => ({ routes: mediaReady ? { vision: { providerId: 'vision', modelId: 'vision-model' } } : {} }),
    route: async () => ({ providerId: 'fixture-provider', model: 'fixture-model', workingDir: source.root }),
    prepare: async () => ({ context: '', tools: [], outputs: () => [], laneSessionId: 'synthetic-lane' }),
    start,
    confirm: async (request) => {
      request.assertCurrent();
      return {
        approved: true, paths: [],
        coverage: { memory: [source.root], 'durable-files': [source.durableRoot] },
        legacyNamespace: null,
        sourceRoots: { root: source.root, durableRoot: source.durableRoot, historicalAbsenceReviewed: true },
      };
    },
  };
  const createCall = () => {
    const host = createRestrictedPartnerHost(deps);
    return (request: unknown) => host(pluginId, request, guard) as Promise<any>;
  };
  const call = createCall();
  const store = createRestrictedPartnerStore(db, guard);
  const requirements = source.requirements(principalId);
  requirements.addressHashes.push('f'.repeat(64));
  const grant = await call({ operation: 'bind', principalId, partnerId, expectedRevision: 0, requirements });
  expect((await call({ operation: 'binding', principalId })).missingRequirements).toEqual([]);
  const resumed = await call({ operation: 'resume', principalId, expectedRevision: grant.revision });
  const channel: RestrictedChannelInput = {
    domainId: 'family', principalId: localPrincipalId, connectionId: 'connection_A',
    generation: 'generation_1', chatId: 'original_chat_A', eventId: 'original_event_A',
    revision: 1, epoch: resumed.dispatchEpoch, memoryRead: true,
  };
  const inputId = hash([channel.connectionId, channel.generation, channel.eventId]);
  const request = { operation: 'submit', principalId, partnerId, grantRevision: grant.revision,
    inputId, text: 'Synthetic original input', channel };
  const waitUnknown = async (runId: string) => {
    for (let i = 0; i < 30; i++) {
      const current = await call({ operation: 'get', principalId, runId });
      if (!current.runningObserved) {
        expect(current.state).toBe('UNKNOWN');
        return current as RestrictedPartnerClaim;
      }
      await new Promise<void>(resolve => setImmediate(resolve));
    }
    throw Error('Synthetic runner did not settle');
  };
  const ack = await call(request);
  const claim = await waitUnknown(ack.runId);
  const routes: Route[] = requirements.addressHashes.map((addressHash, index) => ({
    domainId: channel.domainId, principalId: channel.principalId,
    connectionId: channel.connectionId, generation: channel.generation, addressHash,
    inputs: index ? [] : [{ inputId: claim.inputId, eventId: claim.channel!.eventId, chatId: claim.channel!.chatId }],
  }));
  const snapshotRequest = (mapping = routes, snapshotId?: string) => ({
    operation: 'launch_snapshot', principalId, partnerId, expectedRevision: grant.revision,
    routes: mapping, ...(snapshotId ? { snapshotId } : {}),
  });
  const fenceRequest = (snapshotId: string, operationId: string = randomUUID()) => ({
    operation: 'launch_fence', principalId, expectedRevision: grant.revision, snapshotId, operationId,
  });
  const rows = () => sqlite.prepare('SELECT * FROM plugin_task_requests ORDER BY id').all();
  const runRow = () => sqlite.prepare('SELECT * FROM plugin_task_requests WHERE id=?').get('restricted-run:' + claim.runId) as { payload: string; revision: number };
  const held = () => sqlite.prepare("SELECT * FROM plugin_task_requests WHERE target_id LIKE 'restricted:launch-held:%'").all() as { payload: string }[];
  return {
    source, sqlite, db, call, store, createCall, start, grant, resumed, channel, inputId, request, claim,
    routes, snapshotRequest, fenceRequest, rows, runRow, held, waitUnknown,
    setMedia: (ready: boolean) => { mediaReady = ready; },
    snapshot: () => call(snapshotRequest()) as Promise<Snapshot>,
    close: () => { sqlite.close(); source.cleanup(); },
  };
}

it('captures without writes, holds the exact UNKNOWN, and admits only fresh GUIDs after explicit resume', async () => {
  const f = await fixture();
  try {
    const original = JSON.stringify(f.runRow());
    const before = f.rows();
    const snapshot = await f.snapshot();
    expect(f.rows()).toEqual(before);
    expect(snapshot).toMatchObject({ version: 1, unresolvedCount: 1, records: [{
      inputId: f.inputId, runId: f.claim.runId, routeHash: 'a'.repeat(64),
      eventId: f.channel.eventId, chatId: f.channel.chatId,
    }] });
    expect(Object.keys(snapshot).sort()).toEqual(['records', 'sha256', 'snapshotId', 'unresolvedCount', 'version']);
    expect(await f.call(f.snapshotRequest(f.routes, snapshot.snapshotId))).toEqual(snapshot);
    expect(f.rows()).toEqual(before);
    const fenced = await f.call(f.fenceRequest(snapshot.snapshotId));
    expect(fenced).toMatchObject({ dispatchEnabled: false, dispatchEpoch: f.resumed.dispatchEpoch + 1,
      unknownPreserved: true, launchHold: { snapshotId: snapshot.snapshotId, sha256: snapshot.sha256,
        heldCount: 1, unknownPreserved: true, retryAllowed: false } });
    expect(JSON.stringify(f.runRow())).toBe(original);
    expect(f.held()).toHaveLength(1);
    expect(JSON.parse(f.held()[0]!.payload)).toMatchObject({
      schema: 'restricted-native-launch-hold/v1', sourceId: 'restricted-run:' + f.claim.runId,
      sourcePayload: f.runRow().payload, sourceRevision: f.runRow().revision,
      inputId: f.inputId, eventId: f.channel.eventId,
    });
    expect(await f.store.unresolvedCount(pluginId, principalId)).toBe(1);
    expect(await f.call({ operation: 'binding', principalId })).toMatchObject({ unresolvedCount: 1 });
    await expect(f.call({ ...f.request, inputId: 'fresh-but-paused' })).rejects.toThrow('PAUSED');
    const resumed = await f.call({ operation: 'resume', principalId, expectedRevision: f.grant.revision });
    const epochChannel = { ...f.channel, epoch: resumed.dispatchEpoch };
    const beforeReplay = f.rows();
    await expect(f.call({ ...f.request, channel: epochChannel })).rejects.toThrow('INPUT_CONFLICT');
    await expect(f.call({ ...f.request, inputId: hash('invented-input-id'), channel: epochChannel })).rejects.toThrow('NO_RESUBMIT');
    const changedGeneration = { ...epochChannel, generation: 'generation_2' };
    await expect(f.call({ ...f.request, inputId: hash([changedGeneration.connectionId, changedGeneration.generation, changedGeneration.eventId]),
      channel: changedGeneration })).rejects.toThrow('NO_RESUBMIT');
    expect(f.rows()).toEqual(beforeReplay);
    expect(f.start).toHaveBeenCalledOnce();
    const freshChannel = { ...epochChannel, eventId: 'fresh_event_B' };
    const fresh = await f.call({ ...f.request,
      inputId: hash([freshChannel.connectionId, freshChannel.generation, freshChannel.eventId]),
      text: 'Synthetic fresh input', channel: freshChannel });
    expect(fresh).toMatchObject({ accepted: true, state: 'UNKNOWN' });
    await f.waitUnknown(fresh.runId);
    expect(f.start).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(f.runRow())).toBe(original);
    expect(await f.store.unresolvedCount(pluginId, principalId)).toBe(2);
  } finally { f.close(); }
});

it('rejects forged snapshots, reconstructed handles, and invalid operation UUIDs before any write', async () => {
  const f = await fixture();
  try {
    const snapshot = await f.snapshot();
    const before = f.rows();
    await expect(f.call(f.fenceRequest(randomUUID()))).rejects.toThrow('LAUNCH_UNPROVEN');
    await expect(f.createCall()(f.fenceRequest(snapshot.snapshotId))).rejects.toThrow('LAUNCH_UNPROVEN');
    for (const operationId of ['invented', '12345678-1234-1234-8234-123456789abc', '12345678-1234-4234-1234-123456789abc']) {
      await expect(f.call(f.fenceRequest(snapshot.snapshotId, operationId))).rejects.toThrow('INVALID_PARAMS');
      expect(f.rows()).toEqual(before);
    }
    const grant = (await f.store.readGrant(pluginId, f.grant.grantId))!;
    await expect(holdRestrictedPartnerLaunch(structuredClone(snapshot), f.db, grant,
      { ...grant, dispatchEnabled: false, dispatchEpoch: grant.dispatchEpoch + 1 }, randomUUID(), () => {}))
      .rejects.toThrow('LAUNCH_UNPROVEN');
    expect(f.rows()).toEqual(before);
    expect(f.held()).toEqual([]);
    // Invalid requests did not consume the private capability or change its epoch.
    expect(await f.call(f.snapshotRequest(f.routes, snapshot.snapshotId))).toEqual(snapshot);
    expect(await f.call(f.fenceRequest(snapshot.snapshotId))).toMatchObject({
      dispatchEpoch: f.resumed.dispatchEpoch + 1, launchHold: { heldCount: 1 },
    });
  } finally { f.close(); }
});

it('requires an exact current claim-to-alias mapping and never accepts caller counts or source payloads', async () => {
  const f = await fixture();
  try {
    const before = f.rows();
    const missing = structuredClone(f.routes); missing[0]!.inputs = [];
    const ambiguous = structuredClone(f.routes); ambiguous[1]!.inputs = structuredClone(ambiguous[0]!.inputs);
    const foreignPrincipal = structuredClone(f.routes); foreignPrincipal[0]!.principalId = 'subject_other';
    const foreignConnection = structuredClone(f.routes); foreignConnection[0]!.connectionId = 'connection_other';
    const wrongChat = structuredClone(f.routes); wrongChat[0]!.inputs[0]!.chatId = 'invented_chat';
    const wrongHash = structuredClone(f.routes); wrongHash[0]!.inputs[0]!.inputId = hash('invented');
    const unknownAddress = structuredClone(f.routes); unknownAddress[0]!.addressHash = '9'.repeat(64);
    for (const routes of [missing, ambiguous, foreignPrincipal, foreignConnection, wrongChat, wrongHash, unknownAddress, [f.routes[0]!]]) {
      await expect(f.call(f.snapshotRequest(routes))).rejects.toThrow('LAUNCH_UNPROVEN');
      expect(f.rows()).toEqual(before);
    }
    await expect(f.call({ ...f.snapshotRequest(), unresolvedCount: 0, sourcePayload: f.runRow().payload })).rejects.toThrow('INVALID_PARAMS');
    expect(f.rows()).toEqual(before);
  } finally { f.close(); }
});

it('rejects a snapshot after an authentic late execution receipt changes its original row', async () => {
  const f = await fixture();
  try {
    const snapshot = await f.snapshot();
    expect(await f.store.recordExecution(f.claim.runId, 'late-native-thread', hash('route'))).toBe(true);
    const changed = f.rows();
    await expect(f.call(f.snapshotRequest(f.routes, snapshot.snapshotId))).rejects.toThrow('LAUNCH_UNPROVEN');
    await expect(f.call(f.fenceRequest(snapshot.snapshotId))).rejects.toThrow('LAUNCH_UNPROVEN');
    expect(f.rows()).toEqual(changed);
    expect(f.held()).toEqual([]);
    expect(await f.store.unresolvedCount(pluginId, principalId)).toBe(1);
  } finally { f.close(); }
});

it('rejects a snapshot when only original created_at changes and preserves the UNKNOWN payload', async () => {
  const f = await fixture();
  try {
    const snapshot = await f.snapshot();
    const originalPayload = f.runRow().payload;
    f.sqlite.prepare('UPDATE plugin_task_requests SET created_at=created_at+1 WHERE id=?')
      .run('restricted-run:' + f.claim.runId);
    const changed = f.rows();
    await expect(f.call(f.snapshotRequest(f.routes, snapshot.snapshotId))).rejects.toThrow('LAUNCH_UNPROVEN');
    await expect(f.call(f.fenceRequest(snapshot.snapshotId))).rejects.toThrow('LAUNCH_UNPROVEN');
    expect(f.rows()).toEqual(changed);
    expect(f.runRow().payload).toBe(originalPayload);
    expect(JSON.parse(f.runRow().payload).state).toBe('UNKNOWN');
    expect(f.held()).toEqual([]);
    expect(await f.store.unresolvedCount(pluginId, principalId)).toBe(1);
  } finally { f.close(); }
});

it('requires current reviewed readiness and revalidates original memory sources before fencing', async () => {
  const f = await fixture();
  try {
    const before = f.rows();
    f.setMedia(false);
    await expect(f.snapshot()).rejects.toThrow('REQUIREMENTS_UNMET');
    expect(f.rows()).toEqual(before);
    f.setMedia(true);
    const snapshot = await f.snapshot();
    writeFileSync(path.join(f.source.durableRoot, 'INTERESTS.md'), 'SYNTHETIC changed original source');
    await expect(f.call(f.fenceRequest(snapshot.snapshotId))).rejects.toThrow();
    expect(f.rows()).toEqual(before);
    expect(f.held()).toEqual([]);
    expect(await f.store.unresolvedCount(pluginId, principalId)).toBe(1);
  } finally { f.close(); }
});
