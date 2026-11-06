/** In-process only. Not a plugin API or an authority issuer.
 * Main must supply the authenticated partner-run port; model arguments cannot
 * choose a subject, connection, provider, credential, path or return recipient.
 */
import { createHash } from 'node:crypto';
import {
  ImageChannelRegistry,
  decodeImageResponse,
  assertLibraryEditImageSource,
} from './imageChannelRegistry.js';
import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';
import { transcribeLiteLlmAudioFile } from '../voice-input/LiteLlmTranscriptionProvider.js';
import { SpeechSynthesisSession, type SpeechConnection } from '../voice-conversation/speech.js';
import {
  describeImageWithProvider,
  type VisionChannelDeps,
} from '../vision-bridge/vision-channel.js';
import { speechTextSegments } from '../voice-conversation/speechProtocols.js';

export type MediaKind = 'vision' | 'draw' | 'edit' | 'stt' | 'tts';
export type MediaBinding = Readonly<{
  domainId: string;
  principalId: string;
  partnerId: string;
  connectionId: string;
  generation: string;
  chatId: string;
  eventId: string;
  runId: string;
  revision: number;
  epoch: number;
  resourceFingerprint: string;
  providerId: string;
  modelId: string;
  effectSlot: string;
}>;
export type ManagedMedia = Readonly<{
  id: string;
  sha256: string;
  mimeType: string;
  bytes: Uint8Array;
  binding: MediaBinding;
}>;
export type MediaRequest = { kind: MediaKind; text: string; inputId?: string };
export type MediaReceipt = {
  state: 'COMPLETE';
  binding: MediaBinding;
  requestHash: string;
  input?: { id: string; sha256: string };
  text?: string;
  asset?: { id: string; sha256: string; mimeType: string; byteLength: number };
};
export type MediaPermit = {
  binding: MediaBinding;
  kind: MediaKind;
  signal: AbortSignal;
  /** Synchronous live epoch/revision/provider/resource/partner capability check. */
  assertCurrent(): void;
};
export type RestrictedMediaPorts = {
  /** Resolve an opaque main-owned handle. MUST reject model-created objects. */
  authorize(handle: unknown, kind: MediaKind): MediaPermit;
  /** Existing durable run/effect claim, atomically persisted BEFORE dispatch.
   * Any previously claimed slot (including COMPLETE/UNKNOWN) returns false.
   * Digest mismatch must reject, never allocate a replacement slot. */
  claim(binding: MediaBinding, requestHash: string): Promise<boolean>;
  unknown(binding: MediaBinding, requestHash: string): Promise<void>;
  /** Atomic compare-current + store receipt in the same run/effect transaction. */
  complete(permit: MediaPermit, receipt: MediaReceipt): Promise<void>;
  read(permit: MediaPermit, id: string): Promise<ManagedMedia>;
  /** Existing ingestMedia + original run ownership reference; never a free path.
   * Must check current permit atomically with attaching the ownership reference. */
  ingest(permit: MediaPermit, bytes: Uint8Array, mimeType: string): Promise<ManagedMedia>;
  /** Main wires createRestrictedMediaUrlLoader with actual URL grant/egress/stage ports. */
  urlImage?: (
    permit: MediaPermit,
    url: string,
    role: 'output',
  ) => Promise<{ bytes: Uint8Array; mimeType: string; sourceSha256: string }>;
  images: ImageChannelRegistry;
  /** Core Guide entry over ONLY the already-authorized bytes, not a general Agent.
   * Main wires its current restricted context; absence fails before claim. */
  vision?: (permit: MediaPermit) => VisionChannelDeps;
  /** Account configuration resolved by main, not payload or arbitrary URLs. */
  transcription?: (permit: MediaPermit) => {
    proxyApiKey: string;
    baseUrl: string;
    fetch?: typeof fetch;
  };
  speech?: (permit: MediaPermit) => {
    connection: SpeechConnection;
    fetch: typeof fetch;
    voice: string;
  };
  /** Core-only resolved original library blob path for edit; never returned to model. */
  editPath?: (permit: MediaPermit, asset: ManagedMedia) => Promise<string>;
};
const sha = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const MAX_BYTES = 16 * 1024 * 1024;
const fields = [
  'domainId',
  'principalId',
  'partnerId',
  'connectionId',
  'generation',
  'chatId',
  'eventId',
  'runId',
  'revision',
  'epoch',
  'resourceFingerprint',
  'providerId',
  'modelId',
  'effectSlot',
] as const;
const deny = (): never => {
  throw new Error('RESTRICTED_MEDIA_DENIED');
};
function binding(value: MediaBinding): MediaBinding {
  if (
    !value ||
    fields.some((key) =>
      key === 'revision' || key === 'epoch'
        ? !Number.isSafeInteger(value[key]) || Number(value[key]) < 1
        : typeof value[key] !== 'string' || !value[key] || String(value[key]).length > 256,
    )
  )
    deny();
  if (!/^[a-f0-9]{64}$/.test(value.resourceFingerprint)) deny();
  return Object.freeze(Object.fromEntries(fields.map((k) => [k, value[k]]))) as MediaBinding;
}
function equal(a: MediaBinding, b: MediaBinding): boolean {
  return fields.every((k) => a[k] === b[k]);
}
function checked(asset: ManagedMedia, b: MediaBinding, family: 'image/' | 'audio/'): ManagedMedia {
  if (
    !asset ||
    !equal(binding(asset.binding), b) ||
    typeof asset.id !== 'string' ||
    !asset.id ||
    asset.id.length > 256 ||
    !(asset.bytes instanceof Uint8Array) ||
    !asset.bytes.length ||
    asset.bytes.length > MAX_BYTES
  )
    deny();
  const bytes = Uint8Array.from(asset.bytes);
  const mime = sniffMediaMime(bytes);
  if (sha(bytes) !== asset.sha256 || mime !== asset.mimeType || !mime?.startsWith(family)) deny();
  return Object.freeze({ ...asset, bytes, binding: b });
}
function boundedText(text: unknown): string {
  if (typeof text !== 'string' || !text.trim() || Buffer.byteLength(text, 'utf8') > 32_000) deny();
  return text as string;
}
function wav(pcm: Uint8Array, sampleRate: number): Uint8Array {
  if (!pcm.length || pcm.length % 2 || sampleRate !== 24_000) deny();
  const data = Buffer.alloc(44 + pcm.length);
  data.write('RIFF');
  data.writeUInt32LE(36 + pcm.length, 4);
  data.write('WAVEfmt ', 8);
  data.writeUInt32LE(16, 16);
  data.writeUInt16LE(1, 20);
  data.writeUInt16LE(1, 22);
  data.writeUInt32LE(sampleRate, 24);
  data.writeUInt32LE(sampleRate * 2, 28);
  data.writeUInt16LE(2, 32);
  data.writeUInt16LE(16, 34);
  data.write('data', 36);
  data.writeUInt32LE(pcm.length, 40);
  data.set(pcm, 44);
  return data;
}

/** Bound provider JSON before the existing Core parser reads it. */
function boundedVisionFetch(fetcher: typeof fetch): typeof fetch {
  return async (url, init) => {
    const response = await fetcher(url, init);
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      if (!reader) deny();
      for (;;) {
        const part = await reader!.read();
        if (init?.signal?.aborted) deny();
        if (part.value) {
          size += part.value.length;
          if (size > 128 * 1024) deny();
          chunks.push(part.value);
        }
        if (part.done) break;
      }
    } finally {
      await reader?.cancel().catch(() => undefined);
    }
    const bytes = Buffer.concat(chunks);
    return new Response(bytes, { status: response.status, headers: response.headers });
  };
}

export class RestrictedMediaAdapter {
  constructor(private readonly ports: RestrictedMediaPorts) {}
  async execute(handle: unknown, raw: MediaRequest): Promise<MediaReceipt | { state: 'HELD' }> {
    try {
      return await this.executeAuthorized(handle, raw);
    } catch (error) {
      throw new Error(
        error instanceof Error && error.message === 'RESTRICTED_MEDIA_UNKNOWN'
          ? 'RESTRICTED_MEDIA_UNKNOWN'
          : 'RESTRICTED_MEDIA_DENIED',
      );
    }
  }
  private async executeAuthorized(
    handle: unknown,
    raw: MediaRequest,
  ): Promise<MediaReceipt | { state: 'HELD' }> {
    if (
      !raw ||
      !['vision', 'draw', 'edit', 'stt', 'tts'].includes(raw.kind) ||
      Object.keys(raw).some((k) => !['kind', 'text', 'inputId'].includes(k))
    )
      deny();
    const request = Object.freeze({ ...raw, text: boundedText(raw.text) });
    const original = this.ports.authorize(handle, request.kind);
    const b = binding(original.binding);
    const abort = new AbortController();
    const permit: MediaPermit = Object.freeze({
      ...original,
      binding: b,
      signal: AbortSignal.any([original.signal, abort.signal]),
      assertCurrent: () => current(),
    });
    let imageChannel: ReturnType<ImageChannelRegistry['resolve']> | undefined;
    let stopped = false;
    const current = () => {
      if (
        stopped ||
        permit.signal.aborted ||
        permit.kind !== request.kind ||
        !equal(b, binding(original.binding))
      )
        deny();
      original.assertCurrent();
      if (imageChannel && this.ports.images.resolve(b.providerId, b.modelId) !== imageChannel)
        deny();
    };
    current();
    const needsInput = ['vision', 'edit', 'stt'].includes(request.kind);
    if (
      (request.inputId !== undefined &&
        (typeof request.inputId !== 'string' ||
          !request.inputId ||
          request.inputId.length > 256)) ||
      needsInput !== (typeof request.inputId === 'string' && request.inputId.length > 0)
    )
      deny();
    let input: ManagedMedia | undefined;
    if (needsInput) {
      input = checked(
        await this.ports.read(permit, request.inputId!),
        b,
        request.kind === 'stt' ? 'audio/' : 'image/',
      );
      current();
      if (input.id !== request.inputId) deny();
    }
    let path: string | undefined;
    if (request.kind === 'draw' || request.kind === 'edit') {
      imageChannel = this.ports.images.resolve(b.providerId, b.modelId);
      if (request.kind === 'edit') {
        if (imageChannel.supportsEdit === false || !this.ports.editPath) deny();
        path = await this.ports.editPath!(permit, input!);
        current();
        assertLibraryEditImageSource(path);
        if (
          !path
            .replace(/\\/g, '/')
            .includes(`/assets/${input!.sha256.slice(0, 2)}/${input!.sha256}/blob.`)
        )
          deny();
      }
    }
    const vision = request.kind === 'vision' ? this.ports.vision?.(permit) : undefined;
    if (request.kind === 'vision' && (!vision?.resolveBackendRoute || !vision.fetch)) deny();
    const transcription = request.kind === 'stt' ? this.ports.transcription?.(permit) : undefined;
    if (request.kind === 'stt' && (!transcription?.proxyApiKey || !transcription.baseUrl)) deny();
    const speech = request.kind === 'tts' ? this.ports.speech?.(permit) : undefined;
    if (
      request.kind === 'tts' &&
      (!speech ||
        typeof speech.voice !== 'string' ||
        !speech.voice ||
        speech.voice.length > 128 ||
        speechTextSegments(request.text, speech.connection.protocol).length !== 1)
    )
      deny();
    const requestHash = sha(
      JSON.stringify({ binding: b, request, inputHash: input?.sha256, speechVoice: speech?.voice }),
    );
    current();
    if (!(await this.ports.claim(b, requestHash))) return { state: 'HELD' };
    // Claim is durable; any failure from this point holds UNKNOWN, never retries.
    let session: SpeechSynthesisSession | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let removeAbort = () => {};
    try {
      current();
      const work = async (): Promise<MediaReceipt> => {
        let text: string | undefined;
        let bytes: Uint8Array | undefined;
        let mime: string | undefined;
        if (request.kind === 'stt') {
          text = boundedText(
            await transcribeLiteLlmAudioFile({
              ...transcription!,
              model: b.modelId,
              bytes: input!.bytes,
              mimeType: input!.mimeType,
              signal: permit.signal,
              maxResponseBytes: 65536,
            }),
          );
        } else if (request.kind === 'vision') {
          text = boundedText(
            await describeImageWithProvider(
              b.providerId,
              b.modelId,
              {
                imageUrl: `data:${input!.mimeType};base64,${Buffer.from(input!.bytes).toString('base64')}`,
                prompt: request.text,
                signal: permit.signal,
              },
              { ...vision!, fetch: boundedVisionFetch(vision!.fetch!) },
            ),
          );
        } else if (imageChannel) {
          const args = { model: b.modelId, prompt: request.text, signal: permit.signal };
          const response =
            request.kind === 'edit'
              ? await imageChannel.editImage({ ...args, imagePaths: [path!] })
              : await imageChannel.generateImage(args);
          current();
          if (response.data?.length !== 1) deny();
          const first = response.data[0];
          if (first.b64_json && !first.url) {
            if (first.b64_json.length > Math.ceil(MAX_BYTES / 3) * 4) deny();
            const decoded = decodeImageResponse(response);
            bytes = decoded.buffer;
            mime = decoded.mimeType;
          } else if (first.url && !first.b64_json && this.ports.urlImage) {
            const downloaded = await this.ports.urlImage(permit, first.url, 'output');
            current();
            if (downloaded.sourceSha256 !== sha(first.url)) deny();
            bytes = downloaded.bytes;
            mime = downloaded.mimeType;
          } else deny();
        } else if (speech) {
          session = new SpeechSynthesisSession({
            ...speech,
            connection: () => speech.connection,
            assertCurrent: current,
          });
          const result = await session.start({
            requestId: b.effectSlot,
            modelId: b.modelId,
            voice: speech.voice,
            text: request.text,
          });
          current();
          if ('format' in result) {
            bytes = new Uint8Array(result.data);
            mime = 'audio/mpeg';
          } else {
            const chunks: Uint8Array[] = [];
            let size = 0;
            for (;;) {
              const part = await session.read(b.effectSlot);
              current();
              size += part.pcm.byteLength;
              if (size + 44 > MAX_BYTES) deny();
              chunks.push(new Uint8Array(part.pcm));
              if (part.done) break;
            }
            const pcm = new Uint8Array(size);
            let offset = 0;
            for (const chunk of chunks) {
              pcm.set(chunk, offset);
              offset += chunk.length;
            }
            bytes = wav(pcm, result.sampleRate);
            mime = 'audio/wav';
          }
        }
        current();
        let asset: MediaReceipt['asset'];
        if (bytes && mime) {
          if (!bytes.length || bytes.length > MAX_BYTES || sniffMediaMime(bytes) !== mime) deny();
          const expectedHash = sha(bytes);
          const returned = checked(
            await this.ports.ingest(permit, bytes, mime),
            b,
            request.kind === 'tts' ? 'audio/' : 'image/',
          );
          current();
          if (returned.sha256 !== expectedHash || returned.mimeType !== mime) deny();
          asset = {
            id: returned.id,
            sha256: returned.sha256,
            mimeType: mime,
            byteLength: returned.bytes.length,
          };
        }
        return {
          state: 'COMPLETE',
          binding: b,
          requestHash,
          ...(input ? { input: { id: input.id, sha256: input.sha256 } } : {}),
          ...(text ? { text } : {}),
          ...(asset ? { asset } : {}),
        };
      };

      const deadline = new Promise<never>((_, reject) => {
        const stop = () => {
          stopped = true;
          abort.abort();
          session?.cancel();
          reject(new Error('RESTRICTED_MEDIA_STOPPED'));
        };
        timer = setTimeout(stop, 30_000);
        permit.signal.addEventListener('abort', stop, { once: true });
        removeAbort = () => permit.signal.removeEventListener('abort', stop);
      });
      // Every await continuation checks stopped before ingest or receipt publication.
      const receipt = await Promise.race([work(), deadline]);
      current();
      await this.ports.complete(permit, receipt);
      current();
      return receipt;
    } catch {
      stopped = true;
      try {
        await this.ports.unknown(b, requestHash);
      } finally {
        throw new Error('RESTRICTED_MEDIA_UNKNOWN');
      }
    } finally {
      stopped = true;
      clearTimeout(timer);
      removeAbort();
      abort.abort();
      session?.cancel();
    }
  }
}
