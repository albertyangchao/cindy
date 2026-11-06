// Explicit fake marker, not an account secret; preserve the original wire-test bytes.
const syntheticFixtureCredential='synthetic-not-a-credential';
import { afterEach, expect, it, vi } from 'vitest';
const transport = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('../../maker-host/outbound-fetch.js', () => ({ outboundFetch: transport.fetch }));
vi.mock('../../model-access/gatewayKeyRejection.js', () => ({
  reportCindyGatewayKeyRejected: vi.fn(),
}));
import { transcribeLiteLlmAudioFile } from '../LiteLlmTranscriptionProvider.js';
// Unit regression: restricted paid runs need response bounds/cancellation;
// existing ordinary transcription callers have neither input. All IO is fake.
const input = () => ({
  proxyApiKey: syntheticFixtureCredential,
  baseUrl: 'https://synthetic.invalid',
  model: 'fixture',
  bytes: new Uint8Array([1, 2]),
  mimeType: 'audio/wav',
});
afterEach(() => {
  transport.fetch.mockReset();
  vi.useRealTimers();
});
it('bounded current call reuses actual multipart and parses transcript', async () => {
  transport.fetch.mockResolvedValue(new Response(JSON.stringify({ text: 'fixture speech' })));
  expect(await transcribeLiteLlmAudioFile({ ...input(), maxResponseBytes: 1024 })).toBe(
    'fixture speech',
  );
  expect(transport.fetch).toHaveBeenCalledOnce();
  expect(transport.fetch.mock.calls[0][1].redirect).toBe('error');
});
it('aborted permit cannot begin a charge', async () => {
  const controller = new AbortController();
  controller.abort();
  await expect(
    transcribeLiteLlmAudioFile({ ...input(), signal: controller.signal, maxResponseBytes: 1024 }),
  ).rejects.toThrow('cancelled');
  expect(transport.fetch).not.toHaveBeenCalled();
});
it('provider response excess rejects without parse or retry', async () => {
  transport.fetch.mockResolvedValue(new Response('x'.repeat(1025)));
  await expect(transcribeLiteLlmAudioFile({ ...input(), maxResponseBytes: 1024 })).rejects.toThrow(
    'limit',
  );
  expect(transport.fetch).toHaveBeenCalledOnce();
});
it('ordinary caller without optional fences remains compatible', async () => {
  transport.fetch.mockResolvedValue(new Response(JSON.stringify({ text: 'legacy fixture' })));
  expect(await transcribeLiteLlmAudioFile(input())).toBe('legacy fixture');
});

it.each([1024, undefined])(
  'active body cancellation settles without another chunk (budget %s)',
  async (maxResponseBytes) => {
    vi.useFakeTimers();
    const permit = new AbortController();
    let body!: ReadableStreamDefaultController<Uint8Array>;
    const cancelled = vi.fn();
    transport.fetch.mockResolvedValue(
      new Response(
        new ReadableStream<Uint8Array>({
          start(c) {
            body = c;
          },
          cancel: cancelled,
        }),
      ),
    );
    let settled = false;
    const pending = transcribeLiteLlmAudioFile({
      ...input(),
      signal: permit.signal,
      maxResponseBytes,
    });
    const outcome = pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await vi.advanceTimersByTimeAsync(0);
    permit.abort();
    await vi.advanceTimersByTimeAsync(0);
    try {
      expect(cancelled).toHaveBeenCalledOnce();
      expect(settled).toBe(true);
      expect(transport.fetch).toHaveBeenCalledOnce();
    } finally {
      if (!settled) body.close();
      await outcome;
      vi.useRealTimers();
    }
  },
);
it('active request receives and observes the exact cancellation signal without retry', async () => {
  const permit = new AbortController();
  let dispatched!: () => void;
  const started = new Promise<void>((resolve) => {
    dispatched = resolve;
  });
  transport.fetch.mockImplementation(
    (_url, init) =>
      new Promise((_resolve, reject) => {
        expect(init.signal).toBe(permit.signal);
        init.signal.addEventListener('abort', () => reject(new Error('fixture aborted')), {
          once: true,
        });
        dispatched();
      }),
  );
  const pending = transcribeLiteLlmAudioFile({
    ...input(),
    signal: permit.signal,
    maxResponseBytes: 1024,
  });
  const rejected = expect(pending).rejects.toThrow('aborted');
  await started;
  permit.abort();
  await rejected;
  expect(transport.fetch).toHaveBeenCalledOnce();
});
it('UTF8 body budget is bytes rather than characters', async () => {
  transport.fetch.mockResolvedValue(new Response(JSON.stringify({ text: '界'.repeat(400) })));
  await expect(transcribeLiteLlmAudioFile({ ...input(), maxResponseBytes: 1024 })).rejects.toThrow(
    'limit',
  );
  expect(transport.fetch).toHaveBeenCalledOnce();
});
it('body at exact budget succeeds, cumulative excess across chunks rejects', async () => {
  const exact = JSON.stringify({ text: 'x'.repeat(1013) });
  expect(Buffer.byteLength(exact)).toBe(1024);
  transport.fetch.mockResolvedValueOnce(new Response(exact));
  expect(await transcribeLiteLlmAudioFile({ ...input(), maxResponseBytes: 1024 })).toBe(
    'x'.repeat(1013),
  );
  transport.fetch.mockResolvedValueOnce(
    new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(new Uint8Array(512));
          c.enqueue(new Uint8Array(513));
          c.close();
        },
      }),
    ),
  );
  await expect(transcribeLiteLlmAudioFile({ ...input(), maxResponseBytes: 1024 })).rejects.toThrow(
    'limit',
  );
  expect(transport.fetch).toHaveBeenCalledTimes(2);
});
it.each([0, 1023, 131073, Infinity])(
  'invalid budget %s cannot dispatch',
  async (maxResponseBytes) => {
    await expect(transcribeLiteLlmAudioFile({ ...input(), maxResponseBytes })).rejects.toThrow(
      'bound',
    );
    expect(transport.fetch).not.toHaveBeenCalled();
  },
);

it('body abort does not wait for provider cleanup acknowledgement', async () => {
  vi.useFakeTimers();
  const permit = new AbortController();
  const cancelled = vi.fn(() => new Promise<void>(() => {}));
  const response = new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }));
  transport.fetch.mockResolvedValue(response);
  const pending = transcribeLiteLlmAudioFile({
    ...input(),
    signal: permit.signal,
    maxResponseBytes: 1024,
  });
  const rejected = expect(pending).rejects.toThrow('cancelled');
  await vi.advanceTimersByTimeAsync(0);
  permit.abort();
  await rejected;
  expect(cancelled).toHaveBeenCalledOnce();
  expect(response.body!.locked).toBe(false);
  expect(transport.fetch).toHaveBeenCalledOnce();
});
