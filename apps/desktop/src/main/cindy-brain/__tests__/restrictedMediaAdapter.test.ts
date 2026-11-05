import { afterEach, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
const network = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('../../maker-host/outbound-fetch.js', () => ({ outboundFetch: network.fetch }));
vi.mock('../../model-access/gatewayKeyRejection.js', () => ({
  reportCindyGatewayKeyRejected: vi.fn(),
}));
import {
  RestrictedMediaAdapter,
  type MediaBinding,
  type ManagedMedia,
  type RestrictedMediaPorts,
  type MediaKind,
} from '../restrictedMediaAdapter.js';
import { ImageChannelRegistry } from '../imageChannelRegistry.js';
// Unit regression: existing codec/transport golds do not exercise original native
// partner authority, paid-slot claims or late output fences. Smallest failing
// input: valid pixels returned after revocation. Observe real dispatch/receipts.
const hash = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
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
function setup(kind: MediaKind = 'draw') {
  const b: MediaBinding = {
    domainId: 'domain',
    principalId: 'subject',
    partnerId: 'partner',
    connectionId: 'connection',
    generation: 'generation',
    chatId: 'chat',
    eventId: 'event',
    runId: 'run',
    revision: 1,
    epoch: 1,
    resourceFingerprint: 'a'.repeat(64),
    providerId: 'provider',
    modelId: 'model',
    effectSlot: 'slot',
  };
  const controller = new AbortController();
  let revoked = false,
    claimed = false;
  const handle = Object.freeze({});
  const permit = {
    binding: b,
    kind,
    signal: controller.signal,
    assertCurrent() {
      if (revoked) throw Error('private diagnostic');
    },
  };
  const image = vi.fn(async () => ({ data: [{ b64_json: png.toString('base64') }] }));
  const images = new ImageChannelRegistry();
  images.register('provider', { ready: () => true, generateImage: image, editImage: image });
  const asset = (bytes: Uint8Array, mimeType: string, id = 'input'): ManagedMedia => ({
    bytes,
    id,
    mimeType,
    sha256: hash(bytes),
    binding: { ...b },
  });
  const fetcher = vi.fn<typeof fetch>(
    async () =>
      new Response(new Uint8Array([1, 2, 3, 4]), { headers: { 'Content-Type': 'audio/pcm' } }),
  );
  const ports: RestrictedMediaPorts = {
    authorize: vi.fn((h, k) => {
      if (h !== handle || k !== kind) throw Error('denied');
      return permit;
    }),
    claim: vi.fn(async () => {
      if (claimed) return false;
      claimed = true;
      return true;
    }),
    unknown: vi.fn(async () => {}),
    complete: vi.fn(async () => {}),
    read: vi.fn(async () =>
      asset(kind === 'stt' ? wav : png, kind === 'stt' ? 'audio/wav' : 'image/png'),
    ),
    ingest: vi.fn(async (_p, bytes, mime) => asset(bytes, mime, 'output')),
    images,
    vision: vi.fn(() => ({
      getProviderById: () => null,
      resolveBackendRoute: () => ({
        upstream: 'https://synthetic.invalid/v1',
        requestPath: '/chat/completions',
        model: 'model',
        authorization: null,
        headers: {},
        wireProtocol: 'openai-chat' as const,
      }),
      fetch: network.fetch,
    })),
    editPath: vi.fn(async () => `/managed/assets/${hash(png).slice(0, 2)}/${hash(png)}/blob.png`),
    transcription: () => ({
      proxyApiKey: 'synthetic-not-a-credential',
      baseUrl: 'https://synthetic.invalid',
    }),
    speech: () => ({
      connection: { baseUrl: 'https://synthetic.invalid/v1', protocol: 'openai', headers: {} },
      fetch: fetcher,
      voice: 'alloy',
    }),
  };
  const request = {
    kind,
    text: 'hello',
    ...(['stt', 'vision', 'edit'].includes(kind) ? { inputId: 'input' } : {}),
  };
  return {
    adapter: new RestrictedMediaAdapter(ports),
    ports,
    b,
    handle,
    permit,
    controller,
    image,
    fetcher,
    asset,
    request,
    revoke: () => {
      revoked = true;
    },
  };
}
afterEach(() => {
  vi.useRealTimers();
  network.fetch.mockReset();
});
it('registered Core image channel produces exact managed image receipt', async () => {
  const s = setup();
  expect(await s.adapter.execute(s.handle, s.request)).toMatchObject({
    state: 'COMPLETE',
    binding: s.b,
    asset: { sha256: hash(png), mimeType: 'image/png', byteLength: png.length },
  });
  expect(s.image).toHaveBeenCalledWith(
    expect.objectContaining({ model: 'model', prompt: 'hello' }),
  );
  expect(s.ports.complete).toHaveBeenCalledOnce();
});
it('actual Core vision sends only owned data URL, authorized model, receives finite text', async () => {
  network.fetch.mockResolvedValue(
    new Response(JSON.stringify({ choices: [{ message: { content: 'one pixel' } }] })),
  );
  const s = setup('vision');
  expect(await s.adapter.execute(s.handle, s.request)).toMatchObject({
    text: 'one pixel',
    input: { sha256: hash(png) },
  });
  const body = JSON.parse(network.fetch.mock.calls[0][1].body);
  expect(body.model).toBe('model');
  expect(JSON.stringify(body)).toContain(png.toString('base64'));
  expect(network.fetch).toHaveBeenCalledOnce();
});
it('actual STT production helper sends multipart authorized model/audio', async () => {
  network.fetch.mockResolvedValue(new Response(JSON.stringify({ text: ' synthetic speech ' })));
  const s = setup('stt');
  expect(await s.adapter.execute(s.handle, s.request)).toMatchObject({
    text: 'synthetic speech',
    input: { sha256: hash(wav) },
  });
  const [url, init] = network.fetch.mock.calls[0];
  expect(url).toBe('https://synthetic.invalid/v1/audio/transcriptions');
  expect(init.body.get('model')).toBe('model');
  expect(init.body.get('file').name).toBe('dictation.wav');
  expect(new Uint8Array(await init.body.get('file').arrayBuffer())).toEqual(new Uint8Array(wav));
});
it('actual SpeechSynthesisSession PCM becomes finite playable WAV', async () => {
  const s = setup('tts');
  expect(await s.adapter.execute(s.handle, s.request)).toMatchObject({
    asset: { mimeType: 'audio/wav', byteLength: 48 },
  });
  const bytes = Buffer.from(vi.mocked(s.ports.ingest).mock.calls[0][1]);
  expect(bytes.toString('ascii', 0, 4)).toBe('RIFF');
  expect(bytes.readUInt32LE(40)).toBe(4);
  expect([...bytes.subarray(44)]).toEqual([1, 2, 3, 4]);
  expect(s.fetcher).toHaveBeenCalledOnce();
});
it('unknown paid effect is held and never resubmitted', async () => {
  const s = setup();
  s.image.mockRejectedValue(Error('private body'));
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('RESTRICTED_MEDIA_UNKNOWN');
  expect(await s.adapter.execute(s.handle, s.request)).toEqual({ state: 'HELD' });
  expect(s.image).toHaveBeenCalledOnce();
  expect(s.ports.unknown).toHaveBeenCalledOnce();
});
it('concurrent same-slot requests dispatch once', async () => {
  const s = setup();
  expect(
    (
      await Promise.all([
        s.adapter.execute(s.handle, s.request),
        s.adapter.execute(s.handle, s.request),
      ])
    )
      .map((x) => x.state)
      .sort(),
  ).toEqual(['COMPLETE', 'HELD']);
  expect(s.image).toHaveBeenCalledOnce();
});
it.each([
  'partnerId',
  'principalId',
  'chatId',
  'eventId',
  'runId',
  'providerId',
  'effectSlot',
  'resourceFingerprint',
  'revision',
  'epoch',
] as const)('denies %s input drift before claim', async (key) => {
  const s = setup('vision');
  vi.mocked(s.ports.read).mockResolvedValue({
    ...s.asset(png, 'image/png'),
    binding: { ...s.b, [key]: typeof s.b[key] === 'number' ? 2 : 'b'.repeat(64) },
  });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('DENIED');
  expect(s.ports.claim).not.toHaveBeenCalled();
  expect(s.ports.vision).not.toHaveBeenCalled();
});
it('model authority and free recipient are rejected', async () => {
  const s = setup();
  await expect(s.adapter.execute({}, s.request)).rejects.toThrow('DENIED');
  await expect(
    s.adapter.execute(s.handle, { ...s.request, recipient: 'elsewhere' } as any),
  ).rejects.toThrow('DENIED');
  expect(s.image).not.toHaveBeenCalled();
});
it('hash/MIME/byte excess rejected before claim', async () => {
  for (const change of [
    { sha256: 'b'.repeat(64) },
    { mimeType: 'image/jpeg' },
    { bytes: new Uint8Array(16 * 1024 * 1024 + 1) },
  ]) {
    const s = setup('vision');
    vi.mocked(s.ports.read).mockResolvedValue({ ...s.asset(png, 'image/png'), ...change });
    await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('DENIED');
    expect(s.ports.claim).not.toHaveBeenCalled();
  }
});
it('absent channel or Guide fails before claim', async () => {
  const s = setup();
  s.ports.images.unregister('provider');
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('DENIED');
  expect(s.ports.claim).not.toHaveBeenCalled();
  const v = setup('vision');
  v.ports.vision = undefined;
  await expect(v.adapter.execute(v.handle, v.request)).rejects.toThrow('DENIED');
  expect(v.ports.claim).not.toHaveBeenCalled();
});
it('revocation at provider completion discards output', async () => {
  const s = setup();
  s.image.mockImplementation(async () => {
    s.revoke();
    return { data: [{ b64_json: png.toString('base64') }] };
  });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.ingest).not.toHaveBeenCalled();
  expect(s.ports.complete).not.toHaveBeenCalled();
});
it('30s deadline cannot publish late result or repay', async () => {
  vi.useFakeTimers();
  const s = setup();
  let finish!: (x: any) => void;
  s.image.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = s.adapter.execute(s.handle, s.request);
  const assertion = expect(pending).rejects.toThrow('UNKNOWN');
  await vi.advanceTimersByTimeAsync(30_001);
  await assertion;
  finish({ data: [{ b64_json: png.toString('base64') }] });
  await Promise.resolve();
  await Promise.resolve();
  expect(s.ports.ingest).not.toHaveBeenCalled();
  expect(await s.adapter.execute(s.handle, s.request)).toEqual({ state: 'HELD' });
});
it('abort conserves unknown and blocks ingest', async () => {
  const s = setup();
  s.image.mockImplementation(async () => {
    s.controller.abort();
    return { data: [{ b64_json: png.toString('base64') }] };
  });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.ingest).not.toHaveBeenCalled();
  expect(s.ports.unknown).toHaveBeenCalledOnce();
});
it('cross-subject output never completes handoff', async () => {
  const s = setup();
  vi.mocked(s.ports.ingest).mockImplementation(async (_p, bytes, mime) => ({
    ...s.asset(bytes, mime, 'output'),
    binding: { ...s.b, partnerId: 'other' },
  }));
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.complete).not.toHaveBeenCalled();
});
it('provider non-image bytes do not become image receipt', async () => {
  const s = setup();
  s.image.mockResolvedValue({ data: [{ b64_json: Buffer.from('not image').toString('base64') }] });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.ingest).not.toHaveBeenCalled();
});
it('multiple TTS segments denied before paid claim', async () => {
  const s = setup('tts');
  s.ports.speech = () => ({
    connection: { baseUrl: 'https://synthetic.invalid', protocol: 'qwen-tts', headers: {} },
    fetch: s.fetcher,
    voice: 'alloy',
  });
  await expect(
    s.adapter.execute(s.handle, { ...s.request, text: 'a'.repeat(601) }),
  ).rejects.toThrow('DENIED');
  expect(s.fetcher).not.toHaveBeenCalled();
  expect(s.ports.claim).not.toHaveBeenCalled();
});

it('edit invokes original managed blob with exact source association', async () => {
  const s = setup('edit');
  expect(await s.adapter.execute(s.handle, s.request)).toMatchObject({
    input: { sha256: hash(png) },
    asset: { sha256: hash(png) },
  });
  expect(s.image).toHaveBeenCalledWith(
    expect.objectContaining({
      imagePaths: [`/managed/assets/${hash(png).slice(0, 2)}/${hash(png)}/blob.png`],
    }),
  );
});
it('sidecar or different source blob cannot be edited', async () => {
  const s = setup('edit');
  vi.mocked(s.ports.editPath!).mockResolvedValue(
    '/managed/assets/aa/' + 'a'.repeat(64) + '/meta.json',
  );
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('DENIED');
  expect(s.ports.claim).not.toHaveBeenCalled();
});
it('actual STT failure and empty transcript preserve unknown without raw error', async () => {
  for (const reply of [
    new Response('SENSITIVE_SYNTHETIC_RESPONSE', { status: 503 }),
    new Response('{}'),
  ]) {
    network.fetch.mockResolvedValue(reply);
    const s = setup('stt');
    await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow(
      'RESTRICTED_MEDIA_UNKNOWN',
    );
    expect(s.ports.complete).not.toHaveBeenCalled();
    expect(s.ports.unknown).toHaveBeenCalledOnce();
  }
});
it('odd PCM from actual speech session never becomes WAV', async () => {
  const s = setup('tts');
  s.fetcher.mockResolvedValue(
    new Response(new Uint8Array([1]), { headers: { 'Content-Type': 'audio/pcm' } }),
  );
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.ingest).not.toHaveBeenCalled();
});
it('claim-await revision drift stops before dispatch and holds unknown', async () => {
  const s = setup();
  vi.mocked(s.ports.claim).mockImplementation(async () => {
    s.revoke();
    return true;
  });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.image).not.toHaveBeenCalled();
  expect(s.ports.unknown).toHaveBeenCalledOnce();
});
it('provider removed during claim cannot dispatch cached channel', async () => {
  const s = setup();
  vi.mocked(s.ports.claim).mockImplementation(async () => {
    s.ports.images.unregister('provider');
    return true;
  });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.image).not.toHaveBeenCalled();
});
it('ingest-await revocation cannot complete receipt', async () => {
  const s = setup();
  vi.mocked(s.ports.ingest).mockImplementation(async (_p, bytes, mime) => {
    s.revoke();
    return s.asset(bytes, mime, 'output');
  });
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.complete).not.toHaveBeenCalled();
});

it('ingest receives deadline-aware authority, not just original live epoch', async () => {
  vi.useFakeTimers();
  const s = setup();
  let check!: () => void, release!: (x: any) => void;
  vi.mocked(s.ports.ingest).mockImplementation((p, bytes, mime) => {
    check = p.assertCurrent;
    return new Promise((resolve) => {
      release = () => resolve(s.asset(bytes, mime, 'output'));
    });
  });
  const pending = s.adapter.execute(s.handle, s.request);
  const assertion = expect(pending).rejects.toThrow('UNKNOWN');
  await vi.advanceTimersByTimeAsync(1);
  check();
  await vi.advanceTimersByTimeAsync(30000);
  await assertion;
  expect(() => check()).toThrow('DENIED');
  release(undefined);
  await Promise.resolve();
  expect(s.ports.complete).not.toHaveBeenCalled();
});
it('durable claim stays unknown even when unknown acknowledgement fails', async () => {
  const s = setup();
  s.image.mockRejectedValue(Error('private'));
  vi.mocked(s.ports.unknown).mockRejectedValue(Error('private storage error'));
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('RESTRICTED_MEDIA_UNKNOWN');
  expect(await s.adapter.execute(s.handle, s.request)).toEqual({ state: 'HELD' });
  expect(s.image).toHaveBeenCalledOnce();
});

it('vision response byte excess is bounded before Core JSON parsing', async () => {
  network.fetch.mockResolvedValue(new Response('x'.repeat(128 * 1024 + 1)));
  const s = setup('vision');
  await expect(s.adapter.execute(s.handle, s.request)).rejects.toThrow('UNKNOWN');
  expect(s.ports.complete).not.toHaveBeenCalled();
});

it('model cannot select an account-owned voice or cloning resource', async () => {
  const s = setup('tts');
  await expect(
    s.adapter.execute(s.handle, { ...s.request, voice: 'unapproved' } as any),
  ).rejects.toThrow('DENIED');
  expect(s.fetcher).not.toHaveBeenCalled();
  expect(s.ports.claim).not.toHaveBeenCalled();
});
