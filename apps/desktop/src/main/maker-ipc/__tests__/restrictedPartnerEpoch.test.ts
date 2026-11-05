import { expect, it, vi } from 'vitest';
vi.mock('../../localDb/client/current.js', () => ({ getCurrentDbClientSnapshot: () => null }));
import { createPartnerEpochs } from '../restrictedPartnerEpoch.js';
it('invalidates before async profile commit and never revives an old input on failure', async () => {
  let owner: object | null = {};
  const epochs = createPartnerEpochs(() => owner);
  const old = epochs.capture('bot');
  let release!: () => void;
  const waiting = new Promise<void>((r) => (release = r));
  const write = epochs.change('bot', async () => {
    await waiting;
    throw Error('WRITE_FAILED');
  });
  expect(old).toThrow('REVOKED');
  expect(() => epochs.capture('bot')).toThrow('REVOKED');
  release();
  await expect(write).rejects.toThrow('WRITE_FAILED');
  expect(old).toThrow('REVOKED');
  const fresh = epochs.capture('bot');
  expect(fresh).not.toThrow();
  owner = {};
  expect(fresh).toThrow('REVOKED');
});
it('keeps other partners independent while overlapping changes remain fenced', async () => {
  const epochs = createPartnerEpochs(() => owner);
  const owner = {};
  const other = epochs.capture('other');
  let release!: () => void;
  const slow = epochs.change('bot', () => new Promise<void>((r) => (release = r)));
  await epochs.change('bot', async () => {});
  expect(() => epochs.capture('bot')).toThrow();
  expect(other).not.toThrow();
  release();
  await slow;
  expect(epochs.capture('bot')).not.toThrow();
});
