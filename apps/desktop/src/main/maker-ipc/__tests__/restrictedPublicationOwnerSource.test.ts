import assert from 'node:assert/strict';
import {
  RestrictedPublicationOwnerSource,
  readHeldPublicationOwnerReceipt,
  type PinnedPublicationOwnerSource,
} from '../restrictedPublicationOwnerSource.js';
import type { PublicationSourceBinding } from '../restrictedPublicationCISourceBroker.js';

// The same contract assertions can run without a desktop installation. This is
// an explicit node:test entry, never a Vitest impersonation or a worker mock.
const { describe, it }: {
  describe: (name: string, run: () => void) => unknown;
  it: (name: string, run: () => void | Promise<void>) => unknown;
} = process.env.CINDY_PUBLICATION_OWNER_NODE_TEST === '1'
  ? await import('node:test') : await import('vitest');
type Store = Parameters<typeof RestrictedPublicationOwnerSource.startOwned>[0];
type Row = { revision: number; payload: string };
function fixture() {
  const rows = new Map<string, Row>();
  let reads = 0;
  let afterRead: ((key: string) => void) | undefined;
  const store: Store = {
    consumerGuardReceiptIdentity: {} as Store['consumerGuardReceiptIdentity'],
    async readConsumerGuardReceipt(_plugin, _account, key) {
      reads++;
      const row = rows.get(key);
      const copy = row ? { ...row } : undefined;
      afterRead?.(key);
      return copy;
    },
    async compareAndSwapConsumerGuardReceipt(_plugin, _account, key, previous, payload) {
      assert.ok(Buffer.byteLength(payload) <= 65536);
      const row = rows.get(key);
      if (row?.revision !== previous?.revision || row?.payload !== previous?.payload) return false;
      rows.set(key, { revision: (previous?.revision ?? 0) + 1, payload });
      return true;
    },
    async unresolvedConsumerGuardAdmissions() { throw Error('UNEXPECTED_BUSINESS_QUERY'); },
    async unknownNativePublicationEffects() { throw Error('UNEXPECTED_BUSINESS_QUERY'); },
  };
  const binding: PublicationSourceBinding = {
    accountId: 'a'.repeat(64), deviceId: 'b'.repeat(64), bootId: 'synthetic-boot',
    ownerEpoch: 1, generation: 'synthetic-generation',
  };
  // Invalid before filesystem access; no process is ever started by these unit cases.
  const profile: PinnedPublicationOwnerSource = {
    root: 'not-an-absolute-installed-root', files: {},
    python: { path: '/invalid/python', sha256: 'c'.repeat(64) }, sourceDigest: 'd'.repeat(64),
    instanceId: 'unique-source-instance', profileId: 'canonical-producer', definitionDigest: 'e'.repeat(64),
  };
  const start = (p = profile, b = binding) => RestrictedPublicationOwnerSource.startOwned(
    store, 'synthetic-plugin', 'synthetic-operation', p, b, () => binding);
  return { rows, store, binding, profile, start, reads: () => reads,
    onRead: (hook: (key: string) => void) => { afterRead = hook; } };
}

describe('held publisher source admission boundary', () => {
  it('rejects malformed owner scope before consuming a durable instance', async () => {
    const f = fixture();
    await assert.rejects(f.start(f.profile, { ...f.binding, accountId: 'not-an-account-hash' }), /BINDING/);
    assert.equal(f.rows.size, 0);
    assert.equal(f.reads(), 0);
  });
  it('rejects caller-provided process identity before any launch or ledger write', async () => {
    const f = fixture();
    await assert.rejects(f.start({ ...f.profile, processId: 1 } as PinnedPublicationOwnerSource), /SCHEMA/);
    assert.equal(f.rows.size, 0);
  });
  it('durably consumes an instance before checking launch pins and retains its failed history', async () => {
    const f = fixture();
    await assert.rejects(f.start(), /PROFILE/);
    assert.equal(f.rows.size, 1);
    const [row] = f.rows.values();
    const record = JSON.parse(row.payload);
    assert.equal(record.scope, 'HELD_SOURCE_PROCESS');
    assert.equal(record.processId, null);
    assert.equal(record.state, 'UNKNOWN');
    assert.deepEqual(record.events, [{ state: 'STARTING', processId: null }, { state: 'UNKNOWN', processId: null }]);
    assert.equal(row.revision, 2);
  });
  it('does not restart a consumed instance under a different boot or generation', async () => {
    const f = fixture();
    await assert.rejects(f.start(), /PROFILE/);
    const before = [...f.rows.entries()];
    f.binding.bootId = 'new-boot';
    f.binding.generation = 'new-generation';
    f.binding.ownerEpoch++;
    await assert.rejects(f.start(), /INSTANCE_ALREADY_CLAIMED/);
    assert.deepEqual([...f.rows.entries()], before);
  });
  it('preserves a different CAS winner when cleanup follows a failed launch', async () => {
    const f = fixture();
    f.onRead(key => {
      if (f.reads() === 2) f.rows.set(key, { revision: 9, payload: '{"foreign":"durable-owner-transition"}' });
    });
    await assert.rejects(f.start(), /PROFILE/);
    assert.deepEqual([...f.rows.values()], [{ revision: 9, payload: '{"foreign":"durable-owner-transition"}' }]);
  });
  it('does not accept a JSON observation, copied handle, or prototype as an original receipt', () => {
    const fakeOwner = Object.create(RestrictedPublicationOwnerSource.prototype);
    for (const fake of [{}, { scope: 'HELD_SOURCE_PROCESS', phase: 'LOADED', processId: 1 }, Object.freeze(Object.create(null))])
      assert.throws(() => readHeldPublicationOwnerReceipt(fake, fakeOwner), /PRIVATE_RECEIPT_REQUIRED/);
  });
});
