import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createAnthropicCompatProxy, type ProxyHandle } from './index.js';
let server: Server | undefined;
let proxy: ProxyHandle | undefined;
afterEach(async () => { proxy?.dispose(); await new Promise<void>(resolve => server ? server.close(() => resolve()) : resolve()); });
describe('final outbound non-sensitive parameter observer', () => {
  it.each([false, true])('observes transformed bytes and preserves forwarding if observer throws (%s)', async throws => {
    let received: unknown;
    server = createServer(async (request, response) => {
      let body = ''; for await (const chunk of request) body += chunk;
      received = JSON.parse(body); response.setHeader('content-type', 'application/json'); response.end('{"ok":true}');
    });
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
    const upstream = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const observed: unknown[] = [];
    proxy = await createAnthropicCompatProxy({ upstream,
      transformRequest: [body => ({ ...body as Record<string, unknown>, model: 'gpt-6.1-sol', reasoning: { effort: 'high' }, service_tier: 'default' })],
      onOutboundParameters: parameters => { observed.push(parameters); if (throws) throw new Error('observer unavailable'); } });
    const input = { model: 'before-transform', input: 'private user text', reasoning: { effort: 'low' } };
    const response = await fetch(`${proxy.url}/responses`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input) });
    expect(response.status).toBe(200);
    expect(received).toEqual({ ...input, model: 'gpt-6.1-sol', reasoning: { effort: 'high' }, service_tier: 'default' });
    expect(observed).toEqual([{ model: 'gpt-6.1-sol', effort: 'high', serviceTier: 'default' }]);
  });
});
