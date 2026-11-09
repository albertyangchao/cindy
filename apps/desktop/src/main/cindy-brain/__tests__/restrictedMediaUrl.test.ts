import { afterEach, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
const io = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('../../maker-host/outbound-fetch.js', () => ({ guardedOutboundFetch: io.fetch }));
import { createRestrictedMediaUrlLoader } from '../restrictedMediaUrl.js';
import type { MediaPermit } from '../restrictedMediaAdapter.js';
const sha = (x: string | Uint8Array) => createHash('sha256').update(x).digest('hex');
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWoQAAAAASUVORK5CYII=',
  'base64',
);
// Unit: prior Core downloader has retries and no byte cap. One approved URL is
// the minimal new input; observe real guarded fetch options, bytes and stage claims.
function setup() {
  const controller = new AbortController();
  let revoked = false,
    claimed = false;
  const binding: any = {
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
    modelId: 'model',
    effectSlot: 'effect',
  };
  const permit: MediaPermit = {
    binding,
    kind: 'draw',
    signal: controller.signal,
    assertCurrent() {
      if (revoked) throw Error('revoked');
    },
  };
  const ports = {
    authorize: vi.fn((p: MediaPermit, u: string, role: any) => ({
      binding: p.binding,
      role,
      sourceSha256: sha(u),
      hosts: ['images.example.test'],
      revision: 1,
    })),
    assertCurrent: vi.fn(() => {}),
    claim: vi.fn(async () => {
      if (claimed) return false;
      claimed = true;
      return true;
    }),
    complete: vi.fn(async () => {}),
    unknown: vi.fn(async () => {}),
  };
  const release = vi.fn(async () => {});
  io.fetch.mockResolvedValue({
    response: new Response(png, { headers: { 'content-type': 'image/png' } }),
    release,
  });
  return {
    ports,
    permit,
    controller,
    release,
    loader: createRestrictedMediaUrlLoader(ports),
    revoke: () => {
      revoked = true;
    },
  };
}
afterEach(() => {
  vi.useRealTimers();
  io.fetch.mockReset();
});
it('loads exact approved source bytes via credential-isolated existing guarded fetch once', async () => {
  const s = setup();
  const r = await s.loader(s.permit, 'https://images.example.test/a', 'output');
  expect(r.sha256).toBe(sha(png));
  expect(r.binding).toBe(s.permit.binding);
  expect(io.fetch.mock.calls[0][1]).toMatchObject({
    method: 'GET',
    redirect: 'manual',
    headers: {},
  });
  expect(io.fetch.mock.calls[0][3]).toMatchObject({ allowPrivateNetwork: false, allowHttp: false });
  expect(s.ports.complete).toHaveBeenCalledOnce();
  await expect(s.loader(s.permit, 'https://images.example.test/a', 'output')).rejects.toThrow(
    'HELD',
  );
  expect(io.fetch).toHaveBeenCalledOnce();
});
// Input HEIC must reach the trusted image decoder; adding it to the global blob
// or provider-output whitelist would bypass required normalization.
it('routes byte-sniffed HEIC only as an approved input source and keeps output MIME rules unchanged', async () => {
  const bytes = Buffer.alloc(24); bytes.writeUInt32BE(24); bytes.write('ftyp', 4);
  bytes.write('isom', 8); bytes.write('heic', 16); bytes.write('mif1', 20);
  for (const role of ['input', 'output'] as const) {
    const s = setup();
    io.fetch.mockResolvedValue({ response: new Response(bytes, { headers: { 'content-type': 'image/heic' } }), release: s.release });
    const result = s.loader(s.permit, 'https://images.example.test/source.heic', role);
    if (role === 'input') {
      expect(await result).toMatchObject({ bytes, mimeType: 'image/heic', sha256: sha(bytes), role });
      expect(s.ports.complete).toHaveBeenCalledOnce();
    } else {
      await expect(result).rejects.toThrow('UNKNOWN');
      expect(s.ports.complete).not.toHaveBeenCalled();
      expect(s.ports.unknown).toHaveBeenCalledOnce();
    }
  }
});
it.each([
  'http://images.example.test/a',
  'https://127.0.0.1/a',
  'https://[::1]/a',
  'https://other.test/a',
  'https://user:pass@images.example.test/a',
  'https://images.example.test:8443/a',
  'https://images.example.test/a#fragment',
])('denies URL boundary %s before read claim', async (u) => {
  const s = setup();
  await expect(s.loader(s.permit, u, 'input')).rejects.toThrow('DENIED');
  expect(io.fetch).not.toHaveBeenCalled();
  expect(s.ports.claim).not.toHaveBeenCalled();
});
it('denies wrong grant subject', async () => {
  const s = setup();
  s.ports.authorize.mockImplementation((p, u, role) => ({
    binding: { ...p.binding, principalId: 'other' },
    role,
    sourceSha256: sha(u),
    hosts: ['images.example.test'],
    revision: 1,
  }));
  await expect(s.loader(s.permit, 'https://images.example.test/a', 'input')).rejects.toThrow(
    'DENIED',
  );
  expect(io.fetch).not.toHaveBeenCalled();
});
it.each([302, 404])('never follows redirects or retries HTTP%s', async (status) => {
  const s = setup();
  io.fetch.mockResolvedValue({
    response: new Response(null, { status, headers: { location: 'https://other.test' } }),
    release: s.release,
  });
  await expect(s.loader(s.permit, 'https://images.example.test/a', 'output')).rejects.toThrow(
    'UNKNOWN',
  );
  expect(io.fetch).toHaveBeenCalledOnce();
  expect(s.ports.unknown).toHaveBeenCalledOnce();
});
it('rejects magic/MIME mismatch and byte excess before managed publication', async () => {
  for (const response of [
    new Response(png, { headers: { 'content-type': 'image/jpeg' } }),
    new Response(new Uint8Array(8 * 1024 * 1024 + 1), { headers: { 'content-type': 'image/png' } }),
  ]) {
    const s = setup();
    io.fetch.mockResolvedValue({ response, release: s.release });
    await expect(s.loader(s.permit, 'https://images.example.test/a', 'output')).rejects.toThrow(
      'UNKNOWN',
    );
    expect(s.ports.complete).not.toHaveBeenCalled();
  }
});
it('revocation after fetch prevents result and preserves stage unknown', async () => {
  const s = setup();
  io.fetch.mockImplementation(async () => {
    s.revoke();
    return {
      response: new Response(png, { headers: { 'content-type': 'image/png' } }),
      release: s.release,
    };
  });
  await expect(s.loader(s.permit, 'https://images.example.test/a', 'output')).rejects.toThrow(
    'UNKNOWN',
  );
  expect(s.ports.complete).not.toHaveBeenCalled();
  expect(s.release).toHaveBeenCalledOnce();
});
it('deadline cancels pending body without re-fetch', async () => {
  vi.useFakeTimers();
  const s = setup();
  const cancel = vi.fn();
  io.fetch.mockResolvedValue({
    response: new Response(new ReadableStream<Uint8Array>({ cancel }), {
      headers: { 'content-type': 'image/png' },
    }),
    release: s.release,
  });
  const pending = s.loader(s.permit, 'https://images.example.test/a', 'output');
  const rejected = expect(pending).rejects.toThrow('UNKNOWN');
  await vi.advanceTimersByTimeAsync(15001);
  await rejected;
  expect(cancel).toHaveBeenCalledOnce();
  expect(io.fetch).toHaveBeenCalledOnce();
});
it('address guard denial is held UNKNOWN without private-network exception or retry', async () => {
  const s = setup();
  io.fetch.mockRejectedValue(Error('synthetic address guard denial'));
  await expect(s.loader(s.permit, 'https://images.example.test/a', 'input')).rejects.toThrow(
    'RESTRICTED_MEDIA_URL_UNKNOWN',
  );
  expect(io.fetch).toHaveBeenCalledOnce();
  expect(s.ports.unknown).toHaveBeenCalledOnce();
  expect(s.ports.complete).not.toHaveBeenCalled();
});
