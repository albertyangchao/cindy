import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, it } from 'vitest';
import { createAnthropicCompatProxy } from '@cindy/anthropic-compat-proxy';
import { restrictedPartnerEgressGate } from './restrictedPartnerEgressGate.js';
it('guards every actual HTTP continuation and after an awaited transform, with no secret error', async () => {
  let calls = 0,
    valid = true,
    changeDuringTransform = false;
  const server = createServer((req, res) => {
    calls++;
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const proxy = await createAnthropicCompatProxy({
    upstream: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    transformRequest: [],
    routingTransform: async () => {
      if (changeDuringTransform) {
        await Promise.resolve();
        valid = false;
      }
      return null;
    },
    revalidateBeforeDispatch: restrictedPartnerEgressGate(() => {
      if (!valid) throw Error('PRIVATE_CREDENTIAL_SENTINEL');
    }),
  });
  const post = () =>
    fetch(proxy.url + '/v1/responses', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'fixture', input: 'synthetic' }),
    });
  try {
    const first = await post();
    expect(first.status).toBe(200);
    await first.text();
    expect(calls).toBe(1);
    valid = false;
    const rejected = await post();
    expect(rejected.status).toBe(503);
    expect(await rejected.text()).not.toContain('PRIVATE_CREDENTIAL_SENTINEL');
    expect(calls).toBe(1);
    valid = true;
    changeDuringTransform = true;
    const raced = await post();
    expect(raced.status).toBe(503);
    await raced.text();
    expect(calls).toBe(1);
  } finally {
    await proxy.dispose();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
