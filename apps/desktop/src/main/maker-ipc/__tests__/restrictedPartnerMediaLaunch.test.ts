import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import path from 'node:path';
import sharp from 'sharp';
import { afterEach, expect, it, vi } from 'vitest';
import type { DbClient } from '../../localDb/client/DbClient.js';
import type { MediaKind } from '../../cindy-brain/restrictedMediaAdapter.js';
import { ImageChannelRegistry } from '../../cindy-brain/imageChannelRegistry.js';
import { restrictedMediaAvailability } from '../../cindy-brain/restrictedMediaAvailability.js';
import { grantResourceFingerprint } from '../restrictedPartnerRequirements.js';
import { restrictedPartnerMedia } from '../restrictedPartnerMedia.js';
import { nativeImageUrlAuthority } from '../restrictedPartnerUrlApproval.js';
import { validateRestrictedUrlInput, type RestrictedUrlInputAsset } from '../restrictedPartnerUrlInput.js';
import capturedEditUrl from './fixtures/restrictedMediaUrlEdit.json';
import type {
  RestrictedPartnerGrant,
  RestrictedPartnerClaim,
  RestrictedInputAsset,
} from '../restrictedPartnerExecution.js';

// Test value: actual restrictedPartnerMedia + adapter + registry + SQLite must
// allow an approved edit-only image, and explain absent configuration before a
// media effect is claimed. PLAN W2 requires both behaviors. Earlier integrated
// tests grant vision together with edit and never remove a configured route.
// Minimal failures: one PNG with only edit approved; one approved draw route
// whose configured channel is absent. Unit tier: no external service or files.
// Separate W2 file keeps W1's concurrently owned integrated fixture untouched;
// it exercises media only, with no Bot session/memory lifecycle setup.
const mocks = vi.hoisted(() => ({
  images: undefined as unknown as ImageChannelRegistry,
  routes: {} as NonNullable<RestrictedPartnerGrant['media']>,
  ingest: vi.fn(),
  provider: vi.fn(),
  network: vi.fn(),
  unusedService: vi.fn(() => { throw Error('UNEXPECTED_SERVICE_CALL'); }),
}));

vi.mock('../../maker-host/outbound-fetch.js', () => ({
  outboundFetch: mocks.unusedService,
  guardedOutboundFetch: mocks.network,
}));
vi.mock('../../cindy-brain/index.js', () => ({
  restrictedPartnerImageConfiguration: () => ({ images: mocks.images, routes: mocks.routes }),
  getGhostLibrarySlot: () => ({
    importStream: async () => ({ ok: true }),
    resolvePanelFilePath: async (_plugin: string, relative: string) =>
      path.join(path.parse(process.cwd()).root, 'synthetic-managed', ...relative.split('/')),
  }),
}));
vi.mock('../../maker-host/index.js', () => ({
  restrictedPartnerVisionConfiguration: async () => undefined,
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
// These services are outside this fixture. The actual adapter remains loaded;
// accidentally dispatching vision/voice instead of returning status fails.
vi.mock('../../voice-input/LiteLlmTranscriptionProvider.js', () => ({
  transcribeLiteLlmAudioFile: mocks.unusedService,
}));
vi.mock('../../vision-bridge/vision-channel.js', () => ({
  describeImageWithProvider: mocks.unusedService,
}));
vi.mock('../../mcp-integrations/cindyProxyMedia.js', () => ({
  withCindyMediaBillingSession: (_session: string | undefined, run: () => unknown) => run(),
  withCindyMediaCallGuard: (current: () => void, _fetcher: typeof fetch, run: () => unknown) => {
    current();
    return run();
  },
}));
// Registry's blob-path checks are real. Unrelated Library installation and
// manifest entry points are deliberately unavailable in this media-only test.
vi.mock('../../../shared/ghost.js', () => ({
  GHOST_LIBRARY_CAPABILITIES_V1: Object.freeze({}),
  GHOST_LIBRARY_OPS: [],
  GHOST_PICK_MIN_INTERVAL_MS: 0,
  ghostInstallApprovalToken: mocks.unusedService,
  isSafeGhostRelativePath: mocks.unusedService,
}));
vi.mock('../../../shared/pluginIdentity.js', () => ({
  isArchiveInstanceKey: mocks.unusedService,
  isPluginInstanceKey: mocks.unusedService,
}));

const sha = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWoQAAAAASUVORK5CYII=',
  'base64',
);
const wav = Buffer.alloc(46);
wav.write('RIFF');
wav.writeUInt32LE(38, 4);
wav.write('WAVEfmt ', 8);
wav.writeUInt32LE(16, 16);
wav.writeUInt16LE(1, 20);
wav.writeUInt16LE(1, 22);
wav.writeUInt32LE(24000, 24);
wav.writeUInt32LE(48000, 28);
wav.writeUInt16LE(2, 32);
wav.writeUInt16LE(16, 34);
wav.write('data', 36);
wav.writeUInt32LE(2, 40);

const databases: Database.Database[] = [];
afterEach(() => {
  for (const db of databases.splice(0)) db.close();
  vi.clearAllMocks();
});

function fixture(kind: MediaKind = 'edit') {
  const sql = new Database(':memory:');
  databases.push(sql);
  sql.exec(`CREATE TABLE plugin_task_requests (
    id TEXT PRIMARY KEY, plugin_id TEXT, operation TEXT, target_id TEXT,
    request_key TEXT, fingerprint TEXT, payload TEXT, revision INTEGER,
    created_at INTEGER, UNIQUE(plugin_id,operation,target_id,request_key)
  )`);
  const db = { drizzle: drizzle(sql) } as unknown as DbClient;
  let active = true;
  const current = () => { if (!active) throw Error('REVOKED'); };
  const route = { providerId: 'synthetic', modelId: kind };
  const grant: RestrictedPartnerGrant = {
    version: 1, id: 'grant', pluginId: 'plugin', partnerId: 'partner',
    principalId: sha(JSON.stringify(['domain', 'subject'])), revision: 1,
    enabled: true, dispatchEnabled: true, dispatchEpoch: 1,
    personaSha256: sha('Synthetic persona'), resourceIds: [], resources: [],
    approvalRevision: 'approved', media: { [kind]: route },
  };
  const claim: RestrictedPartnerClaim = {
    version: 1, runId: 'run', inputId: 'input', pluginId: grant.pluginId,
    principalId: grant.principalId, partnerId: grant.partnerId, grantId: grant.id,
    grantRevision: grant.revision, inputSha256: sha('question'),
    inputText: JSON.stringify({ question: 'Synthetic media request', facts: [], documents: [] }),
    state: 'UNKNOWN',
    channel: {
      domainId: 'domain', principalId: 'subject', connectionId: 'connection',
      generation: 'generation', chatId: 'original-chat', eventId: 'original-event',
      revision: 1, epoch: 1, memoryRead: true,
    },
  };
  mocks.routes = kind === 'edit' || kind === 'draw' ? { [kind]: route } : {};
  mocks.provider.mockImplementation(async () => ({ data: [{ b64_json: png.toString('base64') }] }));
  mocks.images = new ImageChannelRegistry();
  mocks.images.register(route.providerId, {
    ready: () => true,
    generateImage: (...args) => mocks.provider(...args),
    editImage: (...args) => mocks.provider(...args),
  });
  mocks.ingest.mockImplementation(async (input: { buffer: Buffer; assertStillValid(): void }, targetDb: unknown) => {
    input.assertStillValid();
    expect(targetDb).toBe(db.drizzle);
    return { ext: '.png' };
  });
  const input = (audio = false): RestrictedInputAsset => {
    const bytes = audio ? wav : png;
    return { id: 'asset:' + sha(bytes), sha256: sha(bytes), sourceSha256: sha(bytes),
      mimeType: audio ? 'audio/wav' : 'image/png', base64: bytes.toString('base64'), partial: false };
  };
  const effects = () => sql.prepare(
    "SELECT payload FROM plugin_task_requests WHERE target_id LIKE 'restricted:effect:%'",
  ).all() as Array<{ payload: string }>;
  return { sql, db, grant, claim, current, input, effects, revoke: () => { active = false; } };
}

it('edit-only original image reaches the actual adapter once and cannot acquire vision or a foreign input', async () => {
  const f = fixture();
  const media = await restrictedPartnerMedia(f.db, f.grant, f.claim, f.current, [f.input()]);
  const inputId = JSON.parse(media.context).authorizedRequestMedia[0].id;
  const tool = media.tools.find((t) => t.name === 'partner_media')!;
  expect(media.availability.edit.state).toBe('READY');
  expect(media.availability.vision.state).toBe('NOT_AUTHORIZED');
  const invoke = (kind: string, id = inputId) => tool.invoke(
    { kind, text: 'Edit these approved pixels', inputId: id },
    { runId: f.claim.runId, callId: 'call' },
  );
  await expect(invoke('vision')).rejects.toThrow('DENIED');
  await expect(invoke('edit', 'asset:foreign')).rejects.toThrow('DENIED');
  expect(mocks.provider).not.toHaveBeenCalled();
  const result = await invoke('edit');
  expect(result.success).toBe(true);
  expect(mocks.provider).toHaveBeenCalledOnce();
  expect(media.outputs()).toMatchObject([{ kind: 'edit', binding: {
    principalId: f.grant.principalId, chatId: 'original-chat', eventId: 'original-event',
  } }]);
  await invoke('edit');
  expect(mocks.provider).toHaveBeenCalledOnce();
  expect(f.effects()).toHaveLength(1);
  expect(JSON.parse(f.effects()[0].payload).state).toBe('COMPLETE');
});

it.each(['vision', 'draw', 'edit', 'stt', 'tts'] as const)(
  'approved %s with no configured service reports NOT_CONFIGURED without a media claim or dispatch',
  async (kind) => {
    const f = fixture(kind);
    mocks.routes = {};
    const needsInput = ['vision', 'edit', 'stt'].includes(kind);
    const media = await restrictedPartnerMedia(f.db, f.grant, f.claim, f.current,
      needsInput ? [f.input(kind === 'stt')] : []);
    const inputId = JSON.parse(media.context).authorizedRequestMedia[0]?.id;
    const tool = media.tools.find((t) => t.name === 'partner_media')!;
    const response = await tool.invoke({ kind, text: 'Synthetic request', ...(needsInput ? { inputId } : {}) },
      { runId: f.claim.runId, callId: 'unconfigured' });
    expect(response.success).toBe(false);
    expect(response.contentItems[0]).toMatchObject({ type: 'inputText' });
    const diagnostic = JSON.parse((response.contentItems[0] as { text: string }).text);
    expect(diagnostic).toMatchObject({ state: 'NOT_CONFIGURED', kind });
    expect(diagnostic.message).toContain('未配置');
    expect(f.effects()).toEqual([]);
    expect(media.outputs()).toEqual([]);
    expect(mocks.provider).not.toHaveBeenCalled();
    expect(mocks.unusedService).not.toHaveBeenCalled();
    expect(mocks.network).not.toHaveBeenCalled();
    await expect(tool.invoke({ kind, text: '', ...(needsInput ? { inputId } : {}) },
      { runId: f.claim.runId, callId: 'empty' })).rejects.toThrow('DENIED');
    if (needsInput) await expect(tool.invoke({ kind, text: 'Synthetic request', inputId: 'asset:foreign' },
      { runId: f.claim.runId, callId: 'foreign' })).rejects.toThrow('DENIED');
    f.revoke();
    await expect(tool.invoke({ kind, text: 'Synthetic request', ...(needsInput ? { inputId } : {}) },
      { runId: f.claim.runId, callId: 'revoked' })).rejects.toThrow('REVOKED');
  },
);

it('availability is only a readonly projection; missing permission and replaced configuration remain denied', async () => {
  const f = fixture();
  const projection = restrictedMediaAvailability(f.grant.media!, {
    edit: { providerId: 'replacement', modelId: 'edit' },
    vision: { providerId: 'configured-but-unapproved', modelId: 'vision' },
  });
  expect(projection.edit.state).toBe('REAPPROVAL_REQUIRED');
  expect(projection.vision.state).toBe('NOT_AUTHORIZED');
  expect(JSON.stringify(projection)).not.toContain('replacement');
  expect(Object.isFrozen(projection)).toBe(true);
  mocks.routes = { edit: { providerId: 'replacement', modelId: 'edit' } };
  await expect(restrictedPartnerMedia(f.db, f.grant, f.claim, f.current, [f.input()]))
    .rejects.toThrow('DENIED');
  f.grant.media = {};
  await expect(restrictedPartnerMedia(f.db, f.grant, f.claim, f.current, [f.input()]))
    .rejects.toThrow('DENIED');
  expect(f.effects()).toEqual([]);
  expect(mocks.provider).not.toHaveBeenCalled();
});

it('the actual plugin edit descriptor validates and completes native URL preparation when approved vision is unavailable', async () => {
  const f = fixture();
  // This fixture was emitted by the actual plugin prepare() entry with live
  // media.vision=false/media.edit=true, not a hand-built Host-only packet.
  const grant = structuredClone(capturedEditUrl.grant) as RestrictedPartnerGrant;
  const claim = structuredClone(capturedEditUrl.claim) as RestrictedPartnerClaim;
  const asset = structuredClone(capturedEditUrl.asset) as RestrictedUrlInputAsset;
  mocks.routes = { edit: grant.media!.edit };
  expect(validateRestrictedUrlInput(grant, claim, asset)).toMatchObject({ modelId: 'edit' });
  expect(() => validateRestrictedUrlInput(grant, claim, {
    ...asset, binding: { ...asset.binding, providerId: 'unapproved' },
  })).toThrow('DENIED');
  expect(() => validateRestrictedUrlInput({ ...grant, media: { vision: grant.media!.vision } }, claim, asset))
    .toThrow('DENIED');
  const downloaded = await sharp({ create: {
    width: 2, height: 2, channels: 3, background: '#778899',
  } }).png().toBuffer();
  mocks.network.mockImplementation(async (_url: string, _init: RequestInit, current: () => void) => {
    current();
    return { response: new Response(downloaded, { headers: { 'content-type': 'image/png' } }), release: async () => {} };
  });
  const show = vi.fn(async () => ({ response: 1, checkboxChecked: false }));
  const native = nativeImageUrlAuthority(grant, f.current, {
    window: () => ({ isDestroyed: () => false }) as never,
    trusted: () => true, show,
  });
  const media = await restrictedPartnerMedia(f.db, grant, claim, f.current, [asset], undefined, native);
  expect(show).toHaveBeenCalledOnce();
  expect(mocks.network).toHaveBeenCalledOnce();
  expect(media.inputText).not.toContain(asset.url);
  const inputId = JSON.parse(media.context).authorizedRequestMedia[0].id;
  const tool = media.tools.find((t) => t.name === 'partner_media')!;
  const unavailable = await tool.invoke({ kind: 'vision', text: 'Describe', inputId },
    { runId: claim.runId, callId: 'vision' });
  expect(unavailable.success).toBe(false);
  expect(f.effects()).toEqual([]);
  expect((await tool.invoke({ kind: 'edit', text: 'Edit approved source', inputId },
    { runId: claim.runId, callId: 'edit' })).success).toBe(true);
  expect(mocks.provider).toHaveBeenCalledOnce();
  expect(media.outputs()).toMatchObject([{ kind: 'edit', binding: { modelId: 'edit' } }]);
});

it('an approved URL whose matching service disappears returns unavailable context before native dialog or download', async () => {
  const f = fixture();
  const grant = structuredClone(capturedEditUrl.grant) as RestrictedPartnerGrant;
  const claim = structuredClone(capturedEditUrl.claim) as RestrictedPartnerClaim;
  const asset = structuredClone(capturedEditUrl.asset) as RestrictedUrlInputAsset;
  mocks.routes = {};
  const show = vi.fn(async () => ({ response: 1, checkboxChecked: false }));
  const native = nativeImageUrlAuthority(grant, f.current, {
    window: () => ({ isDestroyed: () => false }) as never,
    trusted: () => true, show,
  });
  const media = await restrictedPartnerMedia(f.db, grant, claim, f.current, [asset], undefined, native);
  expect(JSON.parse(media.context).unavailableRequestMedia).toEqual([
    { id: asset.id, kind: 'edit', state: 'NOT_CONFIGURED' },
  ]);
  const tool = media.tools.find((t) => t.name === 'partner_media')!;
  const result = await tool.invoke({ kind: 'edit', text: 'Edit original source', inputId: asset.id },
    { runId: claim.runId, callId: 'unavailable-url' });
  expect(result.success).toBe(false);
  expect(f.sql.prepare('SELECT count(*) AS n FROM plugin_task_requests').get()).toEqual({ n: 0 });
  expect(show).not.toHaveBeenCalled();
  expect(mocks.network).not.toHaveBeenCalled();
  expect(mocks.provider).not.toHaveBeenCalled();
});

it('valid partial video with unavailable vision explains configuration before claiming video or frame effects', async () => {
  const f = fixture('vision');
  const sourceSha256 = sha('synthetic-video');
  const channel = f.claim.channel!;
  const video = {
    binding: {
      domainId: channel.domainId, principalId: f.grant.principalId, partnerId: f.grant.partnerId,
      connectionId: channel.connectionId, generation: channel.generation,
      chatId: channel.chatId, eventId: channel.eventId, revision: channel.revision, epoch: channel.epoch,
      runId: 'input:' + f.claim.inputId, resourceFingerprint: grantResourceFingerprint(f.grant),
      providerId: 'synthetic', modelId: 'vision', effectSlot: 'prepare-video:' + sourceSha256,
    },
    sourceId: 'asset:' + sourceSha256, sourceSha256,
    durationSeconds: 1, startSeconds: 0, windowSeconds: 1,
    timeBasis: 'decoder-presentation-timestamp', partial: true as const,
    sampling: 'at-most-three-seeks-one-second-apart',
    frames: [{ index: 0, timestampSeconds: 0, requestedSeconds: 0,
      base64: png.toString('base64'), sha256: sha(png), mimeType: 'image/png' as const }],
  };
  const media = await restrictedPartnerMedia(f.db, f.grant, f.claim, f.current, [{
    type: 'video', id: 'video:' + sha(JSON.stringify(video)), sourceSha256, video,
  }]);
  const tool = media.tools.find((t) => t.name === 'partner_video')!;
  await expect(tool.invoke({ sourceId: 'asset:foreign', text: 'Describe' },
    { runId: f.claim.runId, callId: 'foreign' })).rejects.toThrow('DENIED');
  const result = await tool.invoke({ sourceId: video.sourceId, text: 'Describe' },
    { runId: f.claim.runId, callId: 'video' });
  expect(result.success).toBe(false);
  expect(JSON.parse((result.contentItems[0] as { text: string }).text).state).toBe('NOT_CONFIGURED');
  expect(f.sql.prepare('SELECT count(*) AS n FROM plugin_task_requests').get()).toEqual({ n: 0 });
  expect(mocks.ingest).not.toHaveBeenCalled();
  expect(mocks.unusedService).not.toHaveBeenCalled();
});

it('an edit dispatched before provider failure remains UNKNOWN and cannot be retried as a configuration response', async () => {
  const f = fixture();
  mocks.provider.mockImplementation(async () => { throw Error('synthetic-provider-failure'); });
  const media = await restrictedPartnerMedia(f.db, f.grant, f.claim, f.current, [f.input()]);
  const inputId = JSON.parse(media.context).authorizedRequestMedia[0].id;
  const tool = media.tools.find((t) => t.name === 'partner_media')!;
  const invoke = () => tool.invoke({ kind: 'edit', text: 'Synthetic request', inputId },
    { runId: f.claim.runId, callId: 'unknown' });
  await expect(invoke()).rejects.toThrow('RESTRICTED_MEDIA_UNKNOWN');
  await expect(invoke()).rejects.toThrow('RESTRICTED_MEDIA_UNKNOWN');
  expect(mocks.provider).toHaveBeenCalledOnce();
  expect(f.effects()).toHaveLength(1);
  expect(JSON.parse(f.effects()[0].payload).state).toBe('UNKNOWN');
  expect(() => media.outputs()).toThrow('RESTRICTED_MEDIA_UNKNOWN');
  mocks.routes = {};
  const reopened = await restrictedPartnerMedia(f.db, f.grant, f.claim, f.current, [f.input()]);
  const reopenedTool = reopened.tools.find((t) => t.name === 'partner_media')!;
  await expect(reopenedTool.invoke({ kind: 'edit', text: 'Synthetic request', inputId },
    { runId: f.claim.runId, callId: 'same-unknown-after-config-removal' }))
    .rejects.toThrow('RESTRICTED_MEDIA_UNKNOWN');
  expect(mocks.provider).toHaveBeenCalledOnce();
  expect(f.effects()).toHaveLength(1);
  expect(JSON.parse(f.effects()[0].payload).state).toBe('UNKNOWN');
});
