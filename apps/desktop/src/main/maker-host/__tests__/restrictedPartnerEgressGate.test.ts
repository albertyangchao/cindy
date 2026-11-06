import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, it } from 'vitest';
import { createAnthropicCompatProxy } from '@cindy/anthropic-compat-proxy';
import {
  restrictedPartnerEgressGate,
  restrictedPartnerSpawnArgs,
} from '../restrictedPartnerEgressGate.js';
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

it('rejects protocol adapters with internal fetch/retry before their local handler', async () => {
  let dispatched = 0;
  const proxy = await createAnthropicCompatProxy({
    upstream: 'http://127.0.0.1:1',
    transformRequest: [],
    routingTransform: () => ({
      localHandler: async ({ res }) => {
        dispatched++;
        res.writeHead(200).end('{}');
      },
    }),
    revalidateBeforeDispatch: restrictedPartnerEgressGate(() => {}),
  });
  try {
    const r = await fetch(proxy.url + '/v1/responses', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(r.status).toBe(503);
    await r.text();
    expect(dispatched).toBe(0);
  } finally {
    await proxy.dispose();
  }
});

it('native spawn settings turn off transport resubmission and native code execution for every selected provider', () => {
  const args = restrictedPartnerSpawnArgs(['cindy_gateway', 'cprov_fixture']);
  expect(args).toContain('features.code_mode_only=false');
  for (const id of ['cindy_gateway', 'cprov_fixture'])
    for (const setting of [
      'request_max_retries=0',
      'stream_max_retries=0',
      'supports_websockets=false',
    ])
      expect(args).toContain(`model_providers.${id}.${setting}`);
  expect(() => restrictedPartnerSpawnArgs(['untrusted.path'])).toThrow('ROUTE_UNSUPPORTED');
});
