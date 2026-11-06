import { beforeAll, afterAll, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
vi.mock('../../model-access/gatewayKeyRejection.js', () => ({
  reportCindyGatewayKeyRejected: vi.fn(),
}));
import {
  RestrictedMediaAdapter,
  type MediaBinding,
  type MediaPermit,
  type ManagedMedia,
} from '../restrictedMediaAdapter.js';
import { ImageChannelRegistry } from '../imageChannelRegistry.js';
import { analyzeRestrictedVideo, type PreparedVideo } from '../restrictedVideoInput.js';
const sha = (x: Uint8Array | string) => createHash('sha256').update(x).digest('hex');
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWoQAAAAASUVORK5CYII=',
  'base64',
);
const b: MediaBinding = {
  domainId: 'd',
  principalId: 'p',
  partnerId: 'bot',
  connectionId: 'c',
  generation: 'g',
  chatId: 'chat',
  eventId: 'event',
  runId: 'run',
  revision: 1,
  epoch: 1,
  resourceFingerprint: 'a'.repeat(64),
  providerId: 'provider',
  modelId: 'vision',
  effectSlot: 'video',
};
let prepared: PreparedVideo, folder: string | undefined;
// Unit boundary plus optional real-codec integration fixture. The final leaf gate
// explicitly supplies the registered Bridge decoder; default unit mode tests
// the same managed-frame/actual Core vision path with deterministic PNG frames.
beforeAll(async () => {
  if (process.env.RESTRICTED_VIDEO_PARSER) {
    folder = await mkdtemp(path.join(tmpdir(), 'bb-host-video-'));
    const file = path.join(folder, 'source.mp4');
    execFileSync('ffmpeg', [
      '-v',
      'error',
      '-f',
      'lavfi',
      '-i',
      'testsrc=size=64x48:rate=2',
      '-t',
      '2.5',
      '-pix_fmt',
      'yuv420p',
      file,
    ]);
    const bytes = await readFile(file);
    const code =
      "const {prepareVideo}=require(process.argv[1]);const fs=require('node:fs');const x=JSON.parse(fs.readFileSync(0,'utf8'));const bytes=Buffer.from(x.base64,'base64');prepareVideo(x.binding,{id:'video-source',binding:x.binding,bytes,sha256:x.sha256},{assertCurrent:()=>{}}).then(v=>process.stdout.write(JSON.stringify(v))).catch(()=>process.exit(1));";
    prepared = JSON.parse(
      execFileSync(process.execPath, ['-e', code, process.env.RESTRICTED_VIDEO_PARSER], {
        input: JSON.stringify({ binding: b, base64: bytes.toString('base64'), sha256: sha(bytes) }),
        maxBuffer: 9 * 1024 * 1024,
      }).toString(),
    );
  } else
    prepared = {
      binding: b,
      sourceId: 'video-source',
      sourceSha256: 'b'.repeat(64),
      durationSeconds: 2,
      startSeconds: 0,
      windowSeconds: 2,
      timeBasis: 'decoder-presentation-timestamp',
      partial: true,
      sampling: 'at-most-three-seeks-one-second-apart',
      frames: [0, 1].map((index) => ({
        index,
        timestampSeconds: index,
        requestedSeconds: index,
        base64: png.toString('base64'),
        sha256: sha(png),
        mimeType: 'image/png',
      })),
    };
});
afterAll(async () => {
  if (folder) await rm(folder, { recursive: true, force: true });
});
function setup() {
  let active = true,
    claimed = false;
  const controller = new AbortController();
  const current = () => {
    if (!active) throw Error('revoked');
  };
  const permits = new WeakMap<object, MediaPermit>(),
    assets = new Map<string, ManagedMedia>(),
    effects = new Set<string>();
  const fetcher = vi.fn<typeof fetch>(
    async () =>
      new Response(
        JSON.stringify({ choices: [{ message: { content: 'bounded synthetic frame' } }] }),
      ),
  );
  const adapter = new RestrictedMediaAdapter({
    images: new ImageChannelRegistry(),
    authorize: (handle, kind) => {
      const p = permits.get(handle as object);
      if (!p || p.kind !== kind) throw Error('denied');
      return p;
    },
    claim: async (binding) => {
      if (effects.has(binding.effectSlot)) return false;
      effects.add(binding.effectSlot);
      return true;
    },
    unknown: async () => {},
    complete: async () => {},
    read: async (_p, id) => assets.get(id)!,
    ingest: async () => {
      throw Error('unused');
    },
    vision: () => ({
      getProviderById: () => null,
      resolveBackendRoute: () => ({
        upstream: 'https://fixture.invalid/v1',
        requestPath: '/chat/completions',
        model: 'vision',
        authorization: null,
        headers: {},
        wireProtocol: 'openai-chat',
      }),
      fetch: fetcher,
    }),
  });
  const authority = { binding: b, signal: controller.signal, assertCurrent: current };
  const ports = {
    authorizeSource: vi.fn((_a: any, v: PreparedVideo) => {
      if (v.sourceSha256 !== prepared.sourceSha256) throw Error('source denied');
    }),
    claim: vi.fn(async () => {
      if (claimed) return false;
      claimed = true;
      return true;
    }),
    stage: vi.fn(async (_a: any, binding: MediaBinding, frame: any, bytes: Uint8Array) => {
      current();
      const asset = {
        id: 'frame:' + frame.index,
        binding,
        bytes,
        sha256: sha(bytes),
        mimeType: 'image/png',
      };
      assets.set(asset.id, asset);
      return asset;
    }),
    authorizeFrame: (_a: any, binding: MediaBinding, _asset: ManagedMedia) => {
      const h = {};
      permits.set(h, {
        binding,
        kind: 'vision',
        signal: controller.signal,
        assertCurrent: current,
      });
      return h;
    },
    complete: vi.fn(async () => {}),
    unknown: vi.fn(async () => {}),
  };
  return {
    adapter,
    authority,
    ports,
    fetcher,
    revoke: () => {
      active = false;
    },
  };
}
it('actual prepared video frames stage as managed assets and traverse real Core vision adapter', async () => {
  const s = setup();
  const result = await analyzeRestrictedVideo(
    s.adapter,
    s.ports,
    s.authority,
    prepared,
    'Describe only these frames',
  );
  expect(result).toMatchObject({
    sourceSha256: prepared.sourceSha256,
    partial: true,
    timeBasis: 'decoder-presentation-timestamp',
  });
  expect(s.fetcher).toHaveBeenCalledTimes(prepared.frames.length);
  expect(s.ports.stage).toHaveBeenCalledTimes(prepared.frames.length);
  expect(s.ports.complete).toHaveBeenCalledOnce();
  expect(
    await analyzeRestrictedVideo(
      s.adapter,
      s.ports,
      s.authority,
      prepared,
      'Describe only these frames',
    ),
  ).toEqual({ state: 'HELD' });
  for (const call of s.fetcher.mock.calls) {
    expect(JSON.parse(String(call[1]?.body)).model).toBe('vision');
  }
});
it('foreign subject, hash, excess frame count and ungranted source reject before claim', async () => {
  for (const value of [
    { ...prepared, binding: { ...b, principalId: 'other' } },
    { ...prepared, frames: [{ ...prepared.frames[0], sha256: 'f'.repeat(64) }] },
    { ...prepared, frames: Array(4).fill(prepared.frames[0]) },
    { ...prepared, sourceSha256: 'e'.repeat(64) },
  ]) {
    const s = setup();
    await expect(
      analyzeRestrictedVideo(s.adapter, s.ports, s.authority, value, 'Describe'),
    ).rejects.toThrow();
    expect(s.ports.claim).not.toHaveBeenCalled();
    expect(s.fetcher).not.toHaveBeenCalled();
  }
});
it('revocation after first provider await suppresses completion and holds unknown', async () => {
  const s = setup();
  s.fetcher.mockImplementation(async () => {
    s.revoke();
    return new Response(JSON.stringify({ choices: [{ message: { content: 'late' } }] }));
  });
  await expect(
    analyzeRestrictedVideo(s.adapter, s.ports, s.authority, prepared, 'Describe'),
  ).rejects.toThrow('UNKNOWN');
  expect(s.ports.complete).not.toHaveBeenCalled();
  expect(s.ports.unknown).toHaveBeenCalledOnce();
  expect(s.fetcher).toHaveBeenCalledOnce();
});
