import type { AsrEvent, AsrProvider } from '@cindy/voice-input-core';

import { outboundFetch } from '../maker-host/outbound-fetch.js';
import { reportCindyGatewayKeyRejected } from '../model-access/gatewayKeyRejection.js';
import { elevenLabsLanguageCode } from './language.js';

type LiteLlmTranscriptionProviderOptions = {
  proxyApiKey: string;
  baseUrl: string;
  model?: string;
  sourceLanguage?: string;
};

export type LiteLlmAudioFileTranscriptionInput = {
  /** Main-only scoped transport; ordinary dictation keeps its existing default. */
  fetch?: typeof fetch;
  proxyApiKey: string;
  baseUrl: string;
  model?: string;
  sourceLanguage?: string;
  bytes: Buffer | Uint8Array;
  /** Trusted restricted-run transport fences; absent preserves existing callers. */
  signal?: AbortSignal;
  maxResponseBytes?: number;
  mimeType?: string;
  fileName?: string;
};

/**
 * LiteLLM/XD Gateway transcription provider.
 *
 * The current gateway exposes OpenAI-compatible batch transcription at
 * /v1/audio/transcriptions, not ElevenLabs realtime websocket. This provider
 * keeps credentials and network IO in main and emits the final transcript as a
 * stable ASR event when the user clicks Stop.
 */
export class LiteLlmTranscriptionProvider implements AsrProvider {
  private readonly proxyApiKey: string;
  private readonly baseUrl: string;
  private readonly model: string;
  private readonly sourceLanguage: string;
  private chunks: Buffer[] = [];
  private callback: (event: AsrEvent) => void = () => {};
  private started = false;

  constructor(options: LiteLlmTranscriptionProviderOptions) {
    this.proxyApiKey = options.proxyApiKey;
    this.baseUrl = options.baseUrl;
    this.model = options.model ?? 'elevenlabs/scribe_v2';
    this.sourceLanguage = options.sourceLanguage ?? 'auto';
  }

  onEvent(callback: (event: AsrEvent) => void): void {
    this.callback = callback;
  }

  async start(): Promise<void> {
    if (!this.proxyApiKey) throw new Error('Missing XD Gateway API key');
    if (!this.baseUrl) throw new Error('Missing XD Gateway base URL');
    this.started = true;
    this.chunks = [];
    this.callback({ type: 'connected', at: Date.now() });
  }

  appendAudio(chunk: ArrayBuffer): void {
    if (!this.started) return;
    this.chunks.push(Buffer.from(chunk));
  }

  async flushAudio(): Promise<void> {
    if (!this.started || this.chunks.length === 0) return;
    const pcm = Buffer.concat(this.chunks);
    if (pcm.length === 0) return;

    const wav = makePcm16Wav(pcm, 16_000);
    const transcript = await transcribeLiteLlmAudioFile({
      proxyApiKey: this.proxyApiKey,
      baseUrl: this.baseUrl,
      model: this.model,
      sourceLanguage: this.sourceLanguage,
      bytes: wav,
      mimeType: 'audio/wav',
      fileName: 'dictation.wav',
    }).catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      this.callback({ type: 'error', message, at: Date.now() });
      throw error;
    });
    if (transcript) {
      this.callback({ type: 'stable', text: transcript, at: Date.now() });
    }
  }

  async stop(): Promise<void> {
    this.started = false;
    this.chunks = [];
    this.callback({ type: 'disconnected', at: Date.now() });
  }
}

export async function transcribeLiteLlmAudioFile(
  input: LiteLlmAudioFileTranscriptionInput,
): Promise<string> {
  if (
    input.maxResponseBytes !== undefined &&
    (!Number.isSafeInteger(input.maxResponseBytes) ||
      input.maxResponseBytes < 1024 ||
      input.maxResponseBytes > 131072)
  )
    throw new Error('Invalid transcription response bound');
  if (input.signal?.aborted) throw new Error('Transcription cancelled');
  if (!input.proxyApiKey) throw new Error('Missing XD Gateway API key');
  if (!input.baseUrl) throw new Error('Missing XD Gateway base URL');
  const bytes = input.bytes instanceof Buffer ? input.bytes : Buffer.from(input.bytes);
  if (bytes.byteLength === 0) return '';
  const exact = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const fileName = input.fileName?.trim() || fileNameForMimeType(input.mimeType);
  const mimeType = input.mimeType?.trim() || 'application/octet-stream';
  const form = new FormData();
  form.set('model', input.model ?? 'elevenlabs/scribe_v2');
  const language = elevenLabsLanguageCode(input.sourceLanguage ?? 'auto');
  if (language) form.set('language', language);
  form.set('file', new Blob([exact], { type: mimeType }), fileName);

  const response = await (input.fetch ?? outboundFetch)(
    joinProxyPath(input.baseUrl, '/v1/audio/transcriptions'),
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${input.proxyApiKey}`,
      },
      body: form,
      ...(input.signal ? { signal: input.signal } : {}),
      ...(input.maxResponseBytes ? { redirect: 'error' as const } : {}),
    },
  );

  // proxyApiKey is the Cindy AI key sent to the Cindy gateway. Report on the status
  // before reading the body so an interrupted body read cannot drop the report.
  if (response.status === 401) reportCindyGatewayKeyRejected(input.proxyApiKey);
  const text =
    input.maxResponseBytes !== undefined || input.signal
      ? await boundedTranscriptionText(response, input.maxResponseBytes ?? Infinity, input.signal)
      : await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }

  if (!response.ok) {
    throw new Error(transcriptionErrorMessage(parsed, text, response.status));
  }

  return isRecord(parsed) && typeof parsed.text === 'string' ? parsed.text.trim() : '';
}

function joinProxyPath(baseUrl: string, endpointPath: string): string {
  return `${baseUrl.trim().replace(/\/+$/, '')}/${endpointPath.trim().replace(/^\/+/, '')}`;
}

function fileNameForMimeType(mimeType: string | undefined): string {
  if (mimeType === 'audio/wav' || mimeType === 'audio/wave' || mimeType === 'audio/x-wav')
    return 'dictation.wav';
  if (mimeType === 'audio/mp4' || mimeType === 'audio/m4a' || mimeType === 'audio/x-m4a')
    return 'dictation.m4a';
  if (mimeType === 'audio/mpeg') return 'dictation.mp3';
  if (mimeType === 'audio/webm') return 'dictation.webm';
  if (mimeType === 'audio/ogg') return 'dictation.ogg';
  return 'dictation.bin';
}

function makePcm16Wav(pcm: Buffer, sampleRate: number): Buffer {
  const channels = 1;
  const bitsPerSample = 16;
  const byteRate = sampleRate * channels * (bitsPerSample / 8);
  const blockAlign = channels * (bitsPerSample / 8);
  const header = Buffer.alloc(44);

  header.write('RIFF', 0);
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(channels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bitsPerSample, 34);
  header.write('data', 36);
  header.writeUInt32LE(pcm.length, 40);

  return Buffer.concat([header, pcm]);
}

function transcriptionErrorMessage(parsed: unknown, raw: string, status: number): string {
  if (isRecord(parsed)) {
    const detail = parsed.detail;
    if (typeof detail === 'string') return detail;
    const error = parsed.error;
    if (isRecord(error) && typeof error.message === 'string') return error.message;
    if (typeof parsed.message === 'string') return parsed.message;
  }
  return raw.trim() || `Transcription failed with HTTP ${status}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

async function boundedTranscriptionText(
  response: Response,
  max: number,
  signal?: AbortSignal,
): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Missing transcription response');
  const chunks: Uint8Array[] = [];
  let size = 0;
  let cancelled = false;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    // A provider's cleanup acknowledgement must not delay local cancellation.
    void reader.cancel().catch(() => undefined);
  };
  let onAbort: (() => void) | undefined;
  const aborted = signal
    ? new Promise<never>((_resolve, reject) => {
        onAbort = () => {
          cancel();
          reject(new Error('Transcription cancelled'));
        };
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) onAbort();
      })
    : undefined;
  try {
    for (;;) {
      const next = reader.read();
      const part = await (aborted ? Promise.race([next, aborted]) : next);
      if (signal?.aborted) throw new Error('Transcription cancelled');
      if (part.value) {
        size += part.value.byteLength;
        if (size > max) throw new Error('Transcription response limit');
        chunks.push(Uint8Array.from(part.value));
      }
      if (part.done) break;
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    if (onAbort) signal!.removeEventListener('abort', onAbort);
    cancel();
    reader.releaseLock();
  }
}
