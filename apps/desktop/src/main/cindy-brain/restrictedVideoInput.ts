/** Bounded frame analysis through the existing restricted Core vision adapter. Not a new runner. */
import { createHash } from 'node:crypto';
import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';
import {
  RestrictedMediaAdapter,
  type MediaBinding,
  type ManagedMedia,
} from './restrictedMediaAdapter.js';
const sha = (x: Uint8Array | string) => createHash('sha256').update(x).digest('hex');
export type VideoFrame = {
  index: number;
  timestampSeconds: number;
  requestedSeconds: number;
  base64: string;
  sha256: string;
  mimeType: 'image/png';
};
export type PreparedVideo = {
  binding: MediaBinding;
  sourceId: string;
  sourceSha256: string;
  durationSeconds: number;
  startSeconds: number;
  windowSeconds: number;
  timeBasis: string;
  partial: true;
  sampling: string;
  frames: VideoFrame[];
};
export type VideoAuthority = { binding: MediaBinding; signal: AbortSignal; assertCurrent(): void };
export type VideoPorts = {
  execute?(
    handle: unknown,
    command: { kind: 'vision'; text: string; inputId: string },
  ): ReturnType<RestrictedMediaAdapter['execute']>;
  authorizeSource(authority: VideoAuthority, video: PreparedVideo): void;
  claim(authority: VideoAuthority, sourceSha256: string, windowDigest: string): Promise<boolean>;
  /** Existing guarded ingest, current DB and per-frame provenance; no free path. */
  stage(
    authority: VideoAuthority,
    binding: MediaBinding,
    frame: VideoFrame,
    bytes: Uint8Array,
  ): Promise<ManagedMedia>;
  /** Main mints an actual adapter handle for this exact staged asset/child effect. */
  authorizeFrame(authority: VideoAuthority, binding: MediaBinding, asset: ManagedMedia): unknown;
  complete(authority: VideoAuthority, result: VideoAnalysis): Promise<void>;
  unknown(authority: VideoAuthority): Promise<void>;
};
export type VideoAnalysis = {
  binding: MediaBinding;
  sourceSha256: string;
  sourceId: string;
  partial: true;
  sampling: string;
  startSeconds: number;
  windowSeconds: number;
  timeBasis: string;
  frames: Array<{
    timestampSeconds: number;
    requestedSeconds: number;
    assetSha256: string;
    text: string;
  }>;
};
const deny = (): never => {
  throw Error('RESTRICTED_VIDEO_DENIED');
};
const same = (a: MediaBinding, b: MediaBinding) =>
  Object.keys(a).length === Object.keys(b).length &&
  Object.entries(a).every(([k, v]) => b[k as keyof MediaBinding] === v);
export function validatePreparedVideo(video: PreparedVideo, expected: MediaBinding) {
  if (
    !video ||
    Object.keys(video).some(
      (k) =>
        ![
          'binding',
          'sourceId',
          'sourceSha256',
          'durationSeconds',
          'startSeconds',
          'windowSeconds',
          'timeBasis',
          'partial',
          'sampling',
          'frames',
        ].includes(k),
    ) ||
    typeof video.sourceId !== 'string' ||
    video.sourceId.length > 256 ||
    !same(video.binding, expected) ||
    !video.sourceId ||
    !/^[a-f0-9]{64}$/.test(video.sourceSha256) ||
    video.partial !== true ||
    video.timeBasis !== 'decoder-presentation-timestamp' ||
    video.sampling !== 'at-most-three-seeks-one-second-apart' ||
    !Array.isArray(video.frames) ||
    !video.frames.length ||
    video.frames.length > 3 ||
    !Number.isFinite(video.durationSeconds) ||
    video.durationSeconds <= 0 ||
    video.durationSeconds > 3600 ||
    !Number.isFinite(video.startSeconds) ||
    video.startSeconds < 0 ||
    video.startSeconds >= video.durationSeconds ||
    !Number.isFinite(video.windowSeconds) ||
    video.windowSeconds <= 0 ||
    video.windowSeconds > 3
  )
    deny();
  let size = 0;
  const frozen = video.frames.map((f, index) => {
    if (
      Object.keys(f).some(
        (k) =>
          ![
            'index',
            'timestampSeconds',
            'requestedSeconds',
            'base64',
            'sha256',
            'mimeType',
          ].includes(k),
      ) ||
      f.index !== index ||
      f.mimeType !== 'image/png' ||
      typeof f.base64 !== 'string' ||
      f.base64.length > 8 * 1024 * 1024 ||
      !Number.isFinite(f.timestampSeconds) ||
      f.timestampSeconds < 0 ||
      f.timestampSeconds > video.durationSeconds ||
      !Number.isFinite(f.requestedSeconds) ||
      f.requestedSeconds !== video.startSeconds + index
    )
      deny();
    const bytes = Buffer.from(f.base64, 'base64');
    size += bytes.length;
    if (
      size > 6 * 1024 * 1024 ||
      bytes.toString('base64') !== f.base64 ||
      sha(bytes) !== f.sha256 ||
      sniffMediaMime(bytes) !== 'image/png'
    )
      deny();
    return { ...f, bytes };
  });
  return frozen;
}
export async function analyzeRestrictedVideo(
  adapter: RestrictedMediaAdapter,
  ports: VideoPorts,
  authority: VideoAuthority,
  video: PreparedVideo,
  text: string,
): Promise<VideoAnalysis | { state: 'HELD' }> {
  const original = Object.freeze({ ...authority.binding });
  const current = () => {
    if (authority.signal.aborted || !same(original, authority.binding)) deny();
    authority.assertCurrent();
  };
  current();
  if (typeof text !== 'string' || !text.trim() || Buffer.byteLength(text) > 8000) deny();
  const frozen = validatePreparedVideo(video, authority.binding);
  const source = Object.freeze({ ...video, binding: original, frames: frozen });
  ports.authorizeSource(authority, source);
  current();
  const digest = sha(
    JSON.stringify([
      video.sourceSha256,
      video.startSeconds,
      video.windowSeconds,
      text,
      frozen.map((f) => [f.sha256, f.timestampSeconds]),
    ]),
  );
  if (!(await ports.claim(authority, source.sourceSha256, digest))) return { state: 'HELD' };
  try {
    const result: VideoAnalysis = {
      binding: original,
      sourceSha256: source.sourceSha256,
      sourceId: source.sourceId,
      partial: true,
      sampling: source.sampling,
      startSeconds: source.startSeconds,
      windowSeconds: source.windowSeconds,
      timeBasis: source.timeBasis,
      frames: [],
    };
    let length = 0;
    for (const frame of frozen) {
      current();
      const b = Object.freeze({
        ...original,
        effectSlot: sha(JSON.stringify([authority.binding.effectSlot, digest, frame.index])),
      });
      const asset = await ports.stage(authority, b, frame, frame.bytes);
      current();
      if (
        !same(asset.binding, b) ||
        asset.sha256 !== frame.sha256 ||
        sha(asset.bytes) !== frame.sha256 ||
        asset.mimeType !== 'image/png'
      )
        deny();
      const handle = ports.authorizeFrame(authority, b, asset);
      const command = { kind: 'vision' as const, text, inputId: asset.id };
      const output = await (ports.execute
        ? ports.execute(handle, command)
        : adapter.execute(handle, command));
      current();
      if (
        output.state !== 'COMPLETE' ||
        !same(output.binding, b) ||
        output.input?.sha256 !== frame.sha256 ||
        !output.text
      )
        throw Error('RESTRICTED_VIDEO_DENIED');
      length += Buffer.byteLength(output.text);
      if (length > 32000) deny();
      result.frames.push({
        timestampSeconds: frame.timestampSeconds,
        requestedSeconds: frame.requestedSeconds,
        assetSha256: frame.sha256,
        text: output.text,
      });
    }
    current();
    await ports.complete(authority, result);
    current();
    return result;
  } catch {
    try {
      await ports.unknown(authority);
    } finally {
      throw Error('RESTRICTED_VIDEO_UNKNOWN');
    }
  }
}
