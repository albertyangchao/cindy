import {validateRestrictedUrlInput,projectedUrlInput,normalizeRestrictedUrlImage} from './restrictedPartnerUrlInput.js';
import { isRestrictedHeif } from '../cindy-brain/restrictedMediaImage.js';
import {
  restrictedMediaAvailability,
  restrictedMediaNotConfigured,
} from '../cindy-brain/restrictedMediaAvailability.js';
import {
  analyzeRestrictedVideo,
  validatePreparedVideo,
  type PreparedVideo,
} from '../cindy-brain/restrictedVideoInput.js';
import {
  createRestrictedMediaUrlLoader,
  type MediaUrlPorts,
} from '../cindy-brain/restrictedMediaUrl.js';
import { grantResourceFingerprint } from './restrictedPartnerRequirements.js';
import { createHash } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { pluginTaskRequests } from '../localDb/schema.js';
import type { DbClient } from '../localDb/client/DbClient.js';
import {
  RestrictedMediaAdapter,
  type MediaBinding,
  type MediaKind,
  type ManagedMedia,
  type MediaReceipt,
  type MediaPermit,
} from '../cindy-brain/restrictedMediaAdapter.js';
import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';
import { guardedOutboundFetch } from '../maker-host/outbound-fetch.js';
import {
  withCindyMediaCallGuard,
  withCindyMediaBillingSession,
} from '../mcp-integrations/cindyProxyMedia.js';
import { ingestMedia } from '../cindy-media/ingest.js';
import { captureMediaRefCompensationScope } from '../cindy-media/refCompensationJournal.js';
import type { RestrictedPartnerTool } from '@cindy/maker-core';
import type {
  RestrictedPartnerGrant,
  RestrictedPartnerClaim,
  RestrictedInputAsset,
  RestrictedOutputAsset,
} from './restrictedPartnerExecution.js';
const sha = (x: string | Uint8Array) => createHash('sha256').update(x).digest('hex');
const sameBinding = (a: MediaBinding, b: MediaBinding) =>
  Object.keys(a).length === Object.keys(b).length &&
  Object.keys(a).every((k) => a[k as keyof MediaBinding] === b[k as keyof MediaBinding]);
function fail(): never {
  throw Error('RESTRICTED_MEDIA_DENIED');
}
export async function restrictedMediaConfiguration(
  partnerId: string,
  current: () => void = () => {},
) {
  current();
  const imageModule = await import('../cindy-brain/index.js');
  current();
  const images = imageModule.restrictedPartnerImageConfiguration();
  const vision = await (
    await import('../maker-host/index.js')
  ).restrictedPartnerVisionConfiguration(current);
  current();
  const stt = (await import('../voice-input/index.js')).restrictedPartnerTranscriptionConfiguration(
    current,
  );
  current();
  const tts = await (
    await import('../voice-conversation/index.js')
  ).restrictedPartnerSpeechConfiguration(partnerId, current);
  current();
  return {
    assertCurrent: (kinds: MediaKind[]) => {
      const now = imageModule.restrictedPartnerImageConfiguration().routes;
      for (const k of ['draw', 'edit'] as const)
        if (kinds.includes(k) && JSON.stringify(images.routes[k]) !== JSON.stringify(now[k]))
          fail();
      if (kinds.includes('vision')) vision?.assertCurrent();
      if (kinds.includes('stt')) stt?.assertCurrent();
      if (kinds.includes('tts')) tts?.assertCurrent();
    },
    images: images.images,
    routes: {
      ...images.routes,
      ...(vision ? { vision: vision.route } : {}),
      ...(stt ? { stt: stt.route } : {}),
      ...(tts ? { tts: tts.route } : {}),
    },
    vision: vision?.deps,
    stt: stt?.config,
    tts: tts?.config,
  };
}
/** In-process Main authority; opaque permits/functions never cross NodeRPC. */
export async function restrictedPartnerMedia(
  db: DbClient,
  g: RestrictedPartnerGrant,
  claim: RestrictedPartnerClaim,
  current: () => void,
  inputs: RestrictedInputAsset[],
  laneSessionId?: string,
  urlAuthorization?: Pick<MediaUrlPorts, 'authorize' | 'assertCurrent'> & {
    approve?(permit: MediaPermit, url: string, role: 'input' | 'output'): Promise<void>;
  },
) {
  const inputText=projectedUrlInput(g,claim,inputs);
  const config = await restrictedMediaConfiguration(g.partnerId, current);
  current();
  const routes = g.media ?? {};
  const availability = restrictedMediaAvailability(routes, config.routes);
  const authority = current;
  current = () => {
    authority();
    config.assertCurrent(Object.keys(routes) as MediaKind[]);
  };
  for (const kind of Object.keys(routes) as MediaKind[])
    if (availability[kind].state === 'REAPPROVAL_REQUIRED') fail();
  const imageInputKind = (inputBinding?: MediaBinding) => {
    const candidates = (['vision', 'edit'] as const).filter((kind) => {
      const route = routes[kind];
      return route && (!inputBinding ||
        (route.providerId === inputBinding.providerId && route.modelId === inputBinding.modelId));
    });
    return candidates.find((kind) => availability[kind].state === 'READY') ?? candidates[0];
  };
  const c = claim.channel;
  if (!c) fail();
  const resourceFingerprint = grantResourceFingerprint(g);
  const assets = new Map<string, ManagedMedia>();
  const outputs: RestrictedOutputAsset[] = [];
  let unknown = false;
  let effectCount = 0;
  const signal = new AbortController();
  const makeBinding = (kind: MediaKind, effectSlot: string): MediaBinding => {
    const selected = routes[kind];
    if (!selected) fail();
    return Object.freeze({
      domainId: c!.domainId,
      connectionId: c!.connectionId,
      generation: c!.generation,
      chatId: c!.chatId,
      eventId: c!.eventId,
      revision: c!.revision,
      epoch: c!.epoch,
      principalId: g.principalId,
      partnerId: g.partnerId,
      runId: claim.runId,
      resourceFingerprint,
      providerId: selected!.providerId,
      modelId: selected!.modelId,
      effectSlot,
    });
  };
  const readRow = async (targetId: string) => {
    current();
    const [row] = await db.drizzle
      .select()
      .from(pluginTaskRequests)
      .where(
        and(
          eq(pluginTaskRequests.pluginId, g.pluginId),
          eq(pluginTaskRequests.operation, 'target'),
          eq(pluginTaskRequests.targetId, targetId),
        ),
      )
      .limit(1);
    current();
    return row;
  };
  const insert = async (targetId: string, payload: unknown) => {
    current();
    const raw = JSON.stringify(payload);
    const rows = await db.drizzle
      .insert(pluginTaskRequests)
      .values({
        id: targetId,
        pluginId: g.pluginId,
        operation: 'target',
        targetId,
        requestKey: targetId,
        fingerprint: sha(raw),
        payload: raw,
        revision: 1,
        createdAt: Date.now(),
      })
      .onConflictDoNothing()
      .returning({ id: pluginTaskRequests.id });
    current();
    return rows.length === 1;
  };
  const ingest = async (p: MediaPermit, bytes: Uint8Array, mimeType: string) => {
    p.assertCurrent();
    const data = Buffer.from(bytes);
    const hash = sha(data);
    if (data.length > 4 * 1024 * 1024 || sniffMediaMime(data) !== mimeType) fail();
    const provenanceHash = sha(JSON.stringify([p.binding, hash]));
    const result = await ingestMedia(
      {
        buffer: data,
        mimeType,
        refs: [
          {
            refKind: 'integration-cache',
            refId: 'restricted:' + claim.runId + ':' + provenanceHash,
            originKind: 'integration',
            originId: g.pluginId,
          },
        ],
        assertStillValid: p.assertCurrent,
        refCompensationScope: captureMediaRefCompensationScope(),
      },
      db.drizzle,
    );
    p.assertCurrent();
    const asset = {
      id: 'asset:' + provenanceHash,
      sha256: hash,
      mimeType,
      bytes: Uint8Array.from(data),
      binding: p.binding,
    };
    const target = 'restricted:asset:' + claim.runId + ':' + provenanceHash;
    const saved = {
      version: 1,
      runId: claim.runId,
      grantId: g.id,
      grantRevision: g.revision,
      binding: p.binding,
      hash,
      ext: result.ext,
      mimeType,
    };
    if (!(await insert(target, saved))) {
      const old = await readRow(target);
      if (!old || old.payload !== JSON.stringify(saved)) fail();
    }
    assets.set(asset.id, asset);
    return asset;
  };
  const scopedFetch = (permit: MediaPermit): typeof fetch => {
    let posted = false;
    return async (input, init) => {
      permit.assertCurrent();
      const method = (
        init?.method ?? (input instanceof Request ? input.method : 'GET')
      ).toUpperCase();
      if (method === 'POST') {
        if (posted) fail();
        posted = true;
      }
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const opened = await guardedOutboundFetch(
        url,
        { ...init, signal: permit.signal, redirect: 'manual' },
        permit.assertCurrent,
        {
          targetUrl: new URL(url).href,
          allowHttp: new URL(url).protocol === 'http:',
          allowPrivateNetwork: true,
        },
      );
      const release = () => {
        void opened.release().catch(() => {});
      };
      try {
        permit.assertCurrent();
      } catch {
        release();
        throw Error('RESTRICTED_MEDIA_UNKNOWN');
      }
      const reader = opened.response.body?.getReader();
      if (!reader) {
        release();
        return opened.response;
      }
      return new Response(
        new ReadableStream<Uint8Array>({
          async pull(controller) {
            try {
              permit.assertCurrent();
              const part = await reader.read();
              permit.assertCurrent();
              if (part.done) {
                controller.close();
                release();
              } else controller.enqueue(part.value);
            } catch {
              void reader.cancel().catch(() => {});
              release();
              controller.error(Error('RESTRICTED_MEDIA_UNKNOWN'));
            }
          },
          cancel() {
            void reader.cancel().catch(() => {});
            release();
          },
        }),
        {
          status: opened.response.status,
          statusText: opened.response.statusText,
          headers: opened.response.headers,
        },
      );
    };
  };
  const handles = new WeakMap<object, MediaPermit>();
  const receipts = new Map<string, MediaReceipt>();
  // Main-only explicit approval port; absence keeps URL routes closed.
  const urlStageKey = (p: MediaPermit, source: string, role:'input'|'output') =>
    'restricted:url:' + sha(JSON.stringify([claim.runId, p.binding.effectSlot, source, role]));
  const resultUrlLoader = urlAuthorization
    ? createRestrictedMediaUrlLoader({
        ...urlAuthorization,
        claim: async (p, source, role) => {
          p.assertCurrent();
          return insert(urlStageKey(p, source,p.binding.effectSlot.startsWith('input-url:')?'input':'output'), {
            state: 'UNKNOWN',
            binding: p.binding,
            sourceSha256: source,
            role,
          });
        },
        complete: async (p, source, hash) => {
          p.assertCurrent();
          const old = await readRow(urlStageKey(p, source,p.binding.effectSlot.startsWith('input-url:')?'input':'output'));
          p.assertCurrent();
          if (!old) fail();
          const record = JSON.parse(old!.payload);
          if (
            record.state !== 'UNKNOWN' ||
            record.sourceSha256 !== source ||
            !sameBinding(record.binding, p.binding)
          )
            fail();
          const payload = JSON.stringify({ ...record, state: 'COMPLETE', outputSha256: hash });
          const updated = await db.drizzle
            .update(pluginTaskRequests)
            .set({ payload, fingerprint: sha(payload), revision: 2 })
            .where(
              and(
                eq(pluginTaskRequests.id, old!.id),
                eq(pluginTaskRequests.payload, old!.payload),
                eq(pluginTaskRequests.revision, 1),
              ),
            )
            .returning({ id: pluginTaskRequests.id });
          p.assertCurrent();
          if (updated.length !== 1) fail();
        },
        unknown: async () => {
          unknown = true;
        },
      })
    : undefined;
  const adapter = new RestrictedMediaAdapter({
    ...(resultUrlLoader
      ? {
          urlImage: async (p: MediaPermit, url: string) => {
            await urlAuthorization?.approve?.(p, url, 'output');
            p.assertCurrent();
            return resultUrlLoader(p, url, 'output');
          },
        }
      : {}),
    images: config.images,
    authorize: (h, kind) => {
      if (!h || typeof h !== 'object') fail();
      const p = handles.get(h as object);
      if (!p || p.kind !== kind) fail();
      p!.assertCurrent();
      return p!;
    },
    claim: async (b, requestHash) => {
      current();
      if (++effectCount > 8) fail();
      const ok = await insert('restricted:effect:' + claim.runId + ':' + b.effectSlot, {
        version: 1,
        state: 'UNKNOWN',
        binding: b,
        requestHash,
      });
      if (!ok) unknown = true;
      return ok;
    },
    unknown: async () => {
      unknown = true;
    },
    complete: async (p, receipt) => {
      p.assertCurrent();
      const target = 'restricted:effect:' + claim.runId + ':' + p.binding.effectSlot,
        old = await readRow(target);
      if (!old) fail();
      const record = JSON.parse(old!.payload);
      if (
        record.state !== 'UNKNOWN' ||
        record.requestHash !== receipt.requestHash ||
        !sameBinding(record.binding, p.binding)
      )
        fail();
      const rows = await db.drizzle
        .update(pluginTaskRequests)
        .set({ payload: JSON.stringify(receipt), revision: 2 })
        .where(
          and(
            eq(pluginTaskRequests.id, old!.id),
            eq(pluginTaskRequests.payload, old!.payload),
            eq(pluginTaskRequests.revision, 1),
          ),
        )
        .returning({ id: pluginTaskRequests.id });
      p.assertCurrent();
      if (rows.length !== 1) fail();
      receipts.set(p.binding.effectSlot, receipt);
    },
    read: async (p, id) => {
      p.assertCurrent();
      const source = assets.get(id);
      if (!source) fail();
      return { ...source!, binding: p.binding };
    },
    ingest,
    vision: (permit) => {
      if (!config.vision) fail();
      const base = config.vision!;
      return {
        ...base,
        fetch: scopedFetch(permit),
        getProviderById: (id) => {
          permit.assertCurrent();
          return base.getProviderById(id);
        },
        readCustomProviderKey: (...a) => {
          permit.assertCurrent();
          return base.readCustomProviderKey?.(...a) ?? null;
        },
        readGatewayKey: () => {
          permit.assertCurrent();
          return base.readGatewayKey?.() ?? null;
        },
        resolveBackendRoute: (...a) => {
          permit.assertCurrent();
          return base.resolveBackendRoute?.(...a) ?? null;
        },
      };
    },
    transcription: (permit) => {
      permit.assertCurrent();
      if (!config.stt) fail();
      return { ...config.stt!, fetch: scopedFetch(permit) };
    },
    speech: (permit) => {
      permit.assertCurrent();
      if (!config.tts) fail();
      return { ...config.tts!, fetch: scopedFetch(permit) };
    },
    editPath: async (p, a) => {
      p.assertCurrent();
      const slot = (await import('../cindy-brain/index.js')).getGhostLibrarySlot();
      p.assertCurrent();
      const ext = a.mimeType === 'image/jpeg' ? 'jpg' : a.mimeType === 'image/png' ? 'png' : null;
      if (!ext) fail();
      const rel = `assets/${a.sha256.slice(0, 2)}/${a.sha256}/blob.${ext}`;
      const result = await slot.importStream(g.pluginId, {
        path: rel,
        source: (async function* () {
          yield a.bytes;
        })(),
        totalBytes: a.bytes.length,
        assertCurrent: p.assertCurrent,
      });
      p.assertCurrent();
      if (!result.ok) fail();
      const path = await slot.resolvePanelFilePath(g.pluginId, rel);
      p.assertCurrent();
      if (!path) fail();
      return path!;
    },
  });
  const context: Array<{
    id: string;
    mimeType: string;
    sourceSha256: string;
    normalizedSha256: string;
    partial: boolean;
    sourceFrameCount?: 'NOT_OBSERVED';
    heifFirstImageOnly?: true;
  }> = [];
  const videos = new Map<string, PreparedVideo>();
  const unavailableInputs: Array<{ id: string; kind: MediaKind; state: 'NOT_CONFIGURED' }> = [];
  if (inputs.length > 4) fail();
  let total = 0;
  for (const item of inputs) {
    current();
    if(item.type==='image-url'){
      if(!resultUrlLoader||!urlAuthorization?.approve)fail();
      validateRestrictedUrlInput(g,claim,item);
      const selected=imageInputKind(item.binding);
      if(!selected)fail();
      const b=makeBinding(selected,'input-url:'+item.urlSha256);
      const permit:MediaPermit={binding:b,kind:selected,signal:signal.signal,assertCurrent:current};
      if(availability[selected].state==='NOT_CONFIGURED'){
        if(await readRow(urlStageKey(permit,item.urlSha256,'input'))){
          unknown=true;
          throw Error('RESTRICTED_MEDIA_UNKNOWN');
        }
        unavailableInputs.push({id:item.id,kind:selected,state:'NOT_CONFIGURED'});
        continue;
      }
      await urlAuthorization.approve(permit,item.url,'input');current();
      const downloaded=await resultUrlLoader(permit,item.url,'input');current();
      if(downloaded.sourceSha256!==item.urlSha256||!sameBinding(downloaded.binding,b))fail();
      const bytes=await normalizeRestrictedUrlImage(downloaded.bytes,downloaded.mimeType,current);current();
      total+=bytes.length;if(total>8*1024*1024)fail();
      const prepared=await ingest(permit,bytes,'image/png');current();
      context.push({id:prepared.id,mimeType:'image/png',sourceSha256:downloaded.sha256,normalizedSha256:prepared.sha256,
        partial:isRestrictedHeif(downloaded.mimeType),
        ...(isRestrictedHeif(downloaded.mimeType)?{sourceFrameCount:'NOT_OBSERVED' as const,heifFirstImageOnly:true as const}:{})});
      continue;
    }
    if (item.type === 'video') {
      if (!routes.vision || !claim.inputId) fail();
      const prepared = item.video,
        expected = {
          ...makeBinding('vision', 'prepare-video:' + item.sourceSha256),
          runId: 'input:' + claim.inputId,
        };
      const frames = validatePreparedVideo(prepared, expected);
      if (
        item.sourceSha256 !== prepared.sourceSha256 ||
        item.id !== 'video:' + sha(JSON.stringify(prepared)) ||
        prepared.sourceId !== 'asset:' + prepared.sourceSha256
      )
        fail();
      total += frames.reduce((n, f) => n + f.bytes.length, 0);
      if (total > 8 * 1024 * 1024) fail();
      const video = structuredClone(prepared);
      video.binding = makeBinding('vision', 'video:' + item.sourceSha256);
      if (videos.has(video.sourceId)) fail();
      videos.set(video.sourceId, video);
      continue;
    }
    if (
      !item ||
      Object.keys(item).some(
        (k) => !['id', 'sha256', 'mimeType', 'base64', 'sourceSha256', 'partial'].includes(k),
      ) ||
      typeof item.base64 !== 'string' ||
      item.base64.length > 6 * 1024 * 1024 ||
      !/^asset:[a-f0-9]{64}$/.test(item.id) ||
      !/^[a-f0-9]{64}$/.test(item.sourceSha256) ||
      typeof item.partial !== 'boolean'
    )
      fail();
    const bytes = Buffer.from(item.base64, 'base64');
    total += bytes.length;
    if (
      total > 8 * 1024 * 1024 ||
      bytes.toString('base64') !== item.base64 ||
      sha(bytes) !== item.sha256 ||
      item.id !== 'asset:' + item.sha256 ||
      sniffMediaMime(bytes) !== item.mimeType
    )
      fail();
    const kind = item.mimeType.startsWith('image/')
      ? imageInputKind()
      : item.mimeType.startsWith('audio/')
        ? 'stt'
        : null;
    if (!kind || !routes[kind]) fail();
    const b = makeBinding(kind, 'input:' + item.sha256),
      permit: MediaPermit = { binding: b, kind, signal: signal.signal, assertCurrent: current };
    const prepared = await ingest(permit, bytes, item.mimeType);
    current();
    context.push({
      id: prepared.id,
      mimeType: item.mimeType,
      sourceSha256: item.sourceSha256,
      normalizedSha256: item.sha256,
      partial: item.partial,
    });
  }
  const tool: RestrictedPartnerTool = {
    name: 'partner_media',
    description:
      'Use an explicitly approved existing Core vision/drawing/editing/transcription/speech route. inputId must be from this request. No URLs, paths, provider, credentials or recipients. Partial audio is a sample, never a complete transcript.',
    inputSchema: {
      type: 'object',
      properties: {
        kind: { type: 'string', enum: Object.keys(routes) },
        text: { type: 'string', maxLength: 32000 },
        inputId: { type: 'string' },
      },
      required: ['kind', 'text'],
      additionalProperties: false,
    },
    invoke: async (raw) => {
      current();
      const a = (typeof raw === 'string' ? JSON.parse(raw) : raw) as {
        kind: MediaKind;
        text: string;
        inputId?: string;
      };
      if (
        !a ||
        Object.keys(a).some((k) => !['kind', 'text', 'inputId'].includes(k)) ||
        !['vision', 'draw', 'edit', 'stt', 'tts'].includes(a.kind) ||
        !routes[a.kind] ||
        typeof a.text !== 'string'
      )
        fail();
      const slot = sha(JSON.stringify([a.kind, a.text, a.inputId ?? null]));
      if (availability[a.kind].state === 'NOT_CONFIGURED') {
        // Configuration status must not make malformed or foreign inputs valid.
        // Keep this before the durable paid claim. A pre-existing slot remains
        // held even if configuration has disappeared since its dispatch.
        const needsInput = ['vision', 'edit', 'stt'].includes(a.kind);
        const hasInput = typeof a.inputId === 'string' && a.inputId.length > 0;
        if (
          !a.text.trim() ||
          Buffer.byteLength(a.text, 'utf8') > 32_000 ||
          (a.inputId !== undefined && (!hasInput || a.inputId!.length > 256)) ||
          needsInput !== hasInput
        ) fail();
        if (needsInput) {
          const input = assets.get(a.inputId!);
          const family = a.kind === 'stt' ? 'audio/' : 'image/';
          const unavailableUrl = family === 'image/' &&
            unavailableInputs.some((item) => item.id === a.inputId);
          if ((!input || !input.mimeType.startsWith(family)) && !unavailableUrl) fail();
        }
        current();
        if (await readRow('restricted:effect:' + claim.runId + ':' + slot)) {
          unknown = true;
          throw Error('RESTRICTED_MEDIA_UNKNOWN');
        }
        return restrictedMediaNotConfigured(a.kind);
      }
      const prior = receipts.get(slot);
      if (prior)
        return {
          success: true,
          contentItems: [
            {
              type: 'inputText' as const,
              text: JSON.stringify({
                state: 'COMPLETE',
                text: prior.text,
                asset: prior.asset,
                duplicate: true,
              }),
            },
          ],
        };
      const handle = {};
      const b = makeBinding(a.kind, slot);
      const p: MediaPermit = {
        binding: b,
        kind: a.kind,
        signal: signal.signal,
        assertCurrent: () => {
          current();
          if (JSON.stringify(routes[a.kind]) !== JSON.stringify(config.routes[a.kind])) fail();
        },
      };
      handles.set(handle, p);
      try {
        const receipt = await withCindyMediaBillingSession(laneSessionId, () =>
          withCindyMediaCallGuard(p.assertCurrent, scopedFetch(p), () =>
            adapter.execute(handle, a),
          ),
        );
        current();
        if (receipt.state !== 'COMPLETE') fail();
        if (receipt.asset) {
          const asset = assets.get(receipt.asset.id);
          if (!asset || !sameBinding(asset.binding, b)) fail();
          if (
            outputs.length >= 4 ||
            outputs.reduce((n, x) => n + x.base64.length, 0) +
              Math.ceil(asset!.bytes.length / 3) * 4 >
              6 * 1024 * 1024
          )
            fail();
          if (!['draw', 'edit', 'tts'].includes(a.kind)) fail();
          outputs.push({
            kind: a.kind as 'draw' | 'edit' | 'tts',
            id: asset!.id,
            sha256: asset!.sha256,
            mimeType: asset!.mimeType,
            base64: Buffer.from(asset!.bytes).toString('base64'),
            binding: b,
            requestHash: receipt.requestHash,
            inputSha256: receipt.input?.sha256 ?? sha(claim.inputSha256),
          });
        }
        return {
          success: true,
          contentItems: [
            {
              type: 'inputText' as const,
              text: JSON.stringify({
                state: receipt.state,
                text: receipt.text,
                asset: receipt.asset,
                partial: a.inputId
                  ? (context.find((x) => x.id === a.inputId)?.partial ?? false)
                  : false,
              }),
            },
          ],
        };
      } catch {
        throw Error(unknown ? 'RESTRICTED_MEDIA_UNKNOWN' : 'RESTRICTED_MEDIA_DENIED');
      } finally {
        handles.delete(handle);
      }
    },
  };
  const videoTool: RestrictedPartnerTool = {
    name: 'partner_video',
    description:
      'Analyze an authenticated original video source, up to three sampled frames from the first bounded window. This is partial visual sampling with decoder PTS, not full movie/audio comprehension. No URLs or packets.',
    inputSchema: {
      type: 'object',
      properties: { sourceId: { type: 'string' }, text: { type: 'string', maxLength: 8000 } },
      required: ['sourceId', 'text'],
      additionalProperties: false,
    },
    invoke: async (raw) => {
      current();
      const a = (typeof raw === 'string' ? JSON.parse(raw) : raw) as {
        sourceId: string;
        text: string;
      };
      if (
        !a ||
        Object.keys(a).some((k) => !['sourceId', 'text'].includes(k)) ||
        typeof a.text !== 'string' ||
        !a.text.trim() ||
        Buffer.byteLength(a.text) > 8000
      )
        fail();
      const video = videos.get(a.sourceId);
      if (!video) fail();
      const authority = { binding: video!.binding, signal: signal.signal, assertCurrent: current };
      const key =
        'restricted:video:' + sha(JSON.stringify([claim.runId, video!.binding.effectSlot, a.text]));
      const priorVideo = await readRow(key);
      current();
      if (priorVideo) {
        const saved = JSON.parse(priorVideo.payload);
        if (saved.state === 'COMPLETE' && sameBinding(saved.binding, video!.binding))
          return {
            success: true,
            contentItems: [{ type: 'inputText', text: JSON.stringify(saved.result) }],
          };
        unknown = true;
        throw Error('RESTRICTED_MEDIA_UNKNOWN');
      }
      if (availability.vision.state === 'NOT_CONFIGURED') {
        current();
        return restrictedMediaNotConfigured('vision');
      }
      if (effectCount + 1 + video!.frames.length > 8) fail();
      const result = await analyzeRestrictedVideo(
        adapter,
        {
          authorizeSource: (p, v) => {
            current();
            if (
              JSON.stringify(v.binding) !== JSON.stringify(video!.binding) ||
              v.sourceSha256 !== video!.sourceSha256 ||
              v.sourceId !== video!.sourceId ||
              v.frames.some((f, i) => f.sha256 !== video!.frames[i]?.sha256)
            )
              fail();
          },
          claim: async (p, sourceSha256, windowDigest) => {
            current();
            effectCount++;
            const ok = await insert(key, {
              state: 'UNKNOWN',
              binding: p.binding,
              sourceSha256,
              windowDigest,
            });
            if (!ok) unknown = true;
            return ok;
          },
          stage: async (p, b, f, bytes) =>
            ingest(
              { binding: b, kind: 'vision', signal: p.signal, assertCurrent: current },
              bytes,
              'image/png',
            ),
          authorizeFrame: (p, b, asset) => {
            current();
            if (!sameBinding(b, asset.binding)) fail();
            const handle = {};
            handles.set(handle, {
              binding: b,
              kind: 'vision',
              signal: p.signal,
              assertCurrent: current,
            });
            return handle;
          },
          execute: async (handle, command) => {
            const p = handles.get(handle as object);
            if (!p) fail();
            try {
              return await withCindyMediaBillingSession(laneSessionId, () =>
                withCindyMediaCallGuard(current, scopedFetch(p!), () =>
                  adapter.execute(handle, command),
                ),
              );
            } finally {
              handles.delete(handle as object);
            }
          },
          complete: async (p, result) => {
            current();
            const old = await readRow(key);
            if (!old || JSON.parse(old.payload).state !== 'UNKNOWN') fail();
            const payload = JSON.stringify({ state: 'COMPLETE', binding: p.binding, result });
            const changed = await db.drizzle
              .update(pluginTaskRequests)
              .set({ payload, revision: 2, fingerprint: sha(payload) })
              .where(
                and(
                  eq(pluginTaskRequests.id, old!.id),
                  eq(pluginTaskRequests.payload, old!.payload),
                  eq(pluginTaskRequests.revision, 1),
                ),
              )
              .returning({ id: pluginTaskRequests.id });
            current();
            if (changed.length !== 1) fail();
          },
          unknown: async () => {
            unknown = true;
          },
        },
        authority,
        video!,
        a.text,
      );
      current();
      return { success: true, contentItems: [{ type: 'inputText', text: JSON.stringify(result) }] };
    },
  };
  return {
    inputText,
    availability,
    context: JSON.stringify({
      authorizedRequestMedia: context,
      approvedMediaRoutes: routes,
      mediaAvailability: availability,
      unavailableRequestMedia: unavailableInputs,
      authorizedVideoSources: [...videos.values()].map((v) => ({
        sourceId: v.sourceId,
        sourceSha256: v.sourceSha256,
        startSeconds: v.startSeconds,
        windowSeconds: v.windowSeconds,
        timeBasis: v.timeBasis,
        partial: true,
        sampling: v.sampling,
        framePTS: v.frames.map((f) => f.timestampSeconds),
      })),
    }),
    tools: [...(Object.keys(routes).length ? [tool] : []), ...(videos.size ? [videoTool] : [])],
    outputs() {
      current();
      if (unknown) throw Error('RESTRICTED_MEDIA_UNKNOWN');
      return structuredClone(outputs);
    },
  };
}
