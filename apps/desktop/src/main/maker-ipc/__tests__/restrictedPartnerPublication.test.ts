import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { restrictedPublicationLaunchEnvironment } from '../restrictedPublicationLaunch.js';
import { releaseId, wireBinding } from '../restrictedPublicationProtocol.js';
import {
  createNativePublicationAuthority,
  publicationSha,
  type NativePublisherRuntime,
  type NativePublicationRecord,
  type NativePublicationReceipt,
} from '../restrictedPartnerPublication.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { approveNativePublicRelease } from '../restrictedPublicationApproval.js';
import type { DbClient } from '../../localDb/client/DbClient.js';
// Existing strict publisher cases exercise the retained, explicitly enabled path.
beforeEach(() => vi.stubEnv(restrictedPublicationLaunchEnvironment, '1'));
afterEach(() => vi.unstubAllEnvs());
const sha = (x: string) => createHash('sha256').update(x).digest('hex');
function receipt(a: NativePublicationRecord) {
  const r: Omit<NativePublicationReceipt, 'receiptSha256'> = {
    schema: 'bridge-native-html-release/v1',
    nativeActionId: a.nativeActionId,
    actionRevision: a.actionRevision,
    grantId: a.grantId,
    grantRevision: a.grantRevision,
    completedOutputSha256: a.completedOutputSha256,
    artifactSha256: a.artifactSha256!,
    publisherBindingSha256: a.publisherBindingSha256!,
    artifactRelative: a.artifactRelative,
    dispatcher: 'scripts.publish_generic_html_direct',
    delivery_state: 'applied',
    remoteReleaseId: releaseId(wireBinding(a)),
    verifiedSha256: a.artifactSha256,
    public_url_verified: true,
    observedAt: new Date().toISOString(),
  };
  return { ...r, receiptSha256: publicationSha(r) };
}
async function fixture(scenario = 'complete') {
  const sql = new Database(':memory:');
  sql.exec(
    `CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key));`,
  );
  let active = true,
    owner = true;
  const read = () => {
    if (!owner) throw Error('OWNER_CHANGED');
  };
  const current = () => {
    read();
    if (!active) throw Error('REVOKED');
  };
  const db = {
    drizzle: drizzle(sql),
    exec: async (q: string, params: unknown[]) => ({
      changes: sql.prepare(q).run(...params).changes,
    }),
  } as unknown as DbClient;
  const store = createRestrictedPartnerStore(db, read);
  const g: any = {
    version: 1,
    id: sha('grant'),
    revision: 1,
    pluginId: 'plugin',
    principalId: sha(JSON.stringify(['domain', 'subject'])),
    partnerId: 'synthetic-partner',
    enabled: true,
    personaSha256: sha('persona'),
    resourceIds: [],
    resources: [],
    approvalRevision: 'approved',
    dispatchEpoch: 2,
    dispatchEnabled: true,
  };
  await store.compareAndSwapGrant(g, 0);
  const c: any = {
    version: 1,
    runId: 'complete-native-run',
    inputId: 'input',
    pluginId: 'plugin',
    principalId: g.principalId,
    partnerId: g.partnerId,
    grantId: g.id,
    grantRevision: 1,
    inputSha256: sha('original-input'),
    state: scenario === 'unknown-source' ? 'UNKNOWN' : 'COMPLETE',
    nativeThreadId: 'thread',
    outputMessageId: 'output',
    output: 'Synthetic non-personal completed reply',
    laneSessionId: 'lane',
    channel: {
      domainId: 'domain',
      principalId: 'subject',
      connectionId: 'c',
      generation: 'g',
      chatId: 'original-chat',
      eventId: 'original-event',
      revision: 3,
      epoch: 2,
      memoryRead: true,
    },
  };
  sql
    .prepare(`INSERT INTO plugin_task_requests VALUES(?,?,'target',?,?,?,?,4,?)`)
    .run(
      'restricted-run:' + c.runId,
      'plugin',
      'restricted:input:' + c.inputId,
      c.inputId,
      c.inputSha256,
      JSON.stringify(c),
      Date.now(),
    );
  let prompts = 0,
    effects: string[] = [],
    staged: NativePublicationRecord | undefined;
  const runtime: NativePublisherRuntime = {
    identity: sha('reviewed-runtime'),
    publicOrigin: 'https://reports.example.invalid',
    dispatcher: 'scripts.publish_generic_html_direct',
    verify: async () => {
      if (scenario === 'disable-verify') vi.stubEnv(restrictedPublicationLaunchEnvironment, '0');
    },
    inspect: async (a) => ({
      artifactSha256: sha('html'),
      publisherBindingSha256: sha('metadata'),
      completedOutputSha256: a.completedOutputSha256,
      artifactRelative:
        scenario === 'wrong-route' ? 'core/imessage/other.html' : a.artifactRelative,
    }),
    stage: async (a, _text, control) => {
      staged = await control.stageBind();
    },
    apply: async (a, control) => {
      if (scenario !== 'fake-ack') {
        await control.beforeEffect('remote-staging-prepare');
        if (scenario === 'revoke-upload') active = false;
        if (scenario === 'disable-upload') vi.stubEnv(restrictedPublicationLaunchEnvironment, '0');
        await control.beforeEffect('remote-staging-upload');
        await control.beforeEffect('remote-transaction');
      }
      return receipt(staged ?? a);
    },
    dispatch: async (_a, effect) => {
      effects.push(effect);
      return { dispatched: true };
    },
    reconcile: async () => {
      const a = await service.record(staged!.nativeActionId);
      return receipt(a);
    },
  };
  const service = createNativePublicationAuthority(db, 'plugin', read, current, {
    readGrant: (id) => store.readGrant('plugin', id),
    readRun: (id) => store.byRun('plugin', id),
    runtime: () => (scenario === 'runtime-missing' ? undefined : runtime),
    approve: async (input) =>
      approveNativePublicRelease(input, {
        window: () => ({ isDestroyed: () => false }) as any,
        trusted: () => true,
        show: async (_win, options) => {
          prompts++;
          expect(options.defaultId).toBe(0);
          expect(options.checkboxChecked).toBe(false);
          expect(options.detail).toContain(sha(c.output));
          if (scenario === 'late-approval') active = false;
          if (scenario === 'disable-approval') vi.stubEnv(restrictedPublicationLaunchEnvironment, '0');
          return {
            response: scenario === 'cancel' ? 0 : 1,
            checkboxChecked: scenario !== 'private-output',
          };
        },
      }),
  });
  return {
    sql,
    g,
    c,
    service,
    effects,
    prompts: () => prompts,
    revoke: () => {
      active = false;
    },
    accountChange: () => {
      owner = false;
    },
  };
}
it('actual native public approval + real account SQL action claims each effect once and preserves historical fact after revoke', async () => {
  const f = await fixture();
  try {
    const before = JSON.stringify(f.c),
      a = await f.service.prepare(f.g, f.c.runId);
    expect(a.state).toBe('PREPARED_NO_REMOTE_EFFECT');
    expect(a.artifactSha256).toBeNull();
    expect(f.effects).toEqual([]);
    const duplicate = await f.service.prepare(f.g, f.c.runId);
    expect(duplicate.nativeActionId).toBe(a.nativeActionId);
    expect(f.prompts()).toBe(1);
    const result = await f.service.run(f.g, a.nativeActionId);
    expect(result.state).toBe('APPLIED_VERIFIED');
    expect(f.effects).toEqual([
      'remote-staging-prepare',
      'remote-staging-upload',
      'remote-transaction',
    ]);
    const publicMetadata = await f.service.read(f.g, a.nativeActionId);
    expect(publicMetadata.returnAllowed).toBe(true);
    expect(Object.keys(publicMetadata).sort()).toEqual([
      'nativeActionId', 'actionRevision', 'state', 'completedOutputSha256',
      'artifactSha256', 'publisherBindingSha256', 'artifactRelative', 'expiresAt',
      'runtimeReady', 'returnAllowed', 'publicUrl',
    ].sort());
    expect((await f.service.run(f.g, a.nativeActionId)).state).toBe('HELD');
    expect(f.effects).toHaveLength(3);
    f.revoke();
    const historical = await f.service.read(f.g, a.nativeActionId);
    expect(historical.state).toBe('APPLIED_VERIFIED');
    expect(historical.publicUrl).toBeNull();
    expect(historical.returnAllowed).toBe(false);
    expect((await f.service.record(a.nativeActionId)).audit.map((x) => x.to)).toContain(
      'DISPATCHING_UNKNOWN',
    );
    expect(JSON.stringify(f.c)).toBe(before);
  } finally {
    f.sql.close();
  }
});
for (const scenario of [
  'cancel',
  'private-output',
  'late-approval',
  'unknown-source',
  'runtime-missing',
  'disable-verify',
  'disable-approval',
])
  it(
    'publication native boundary ' + scenario + ' cannot reserve or dispatch from a bool/old claim',
    async () => {
      const f = await fixture(scenario);
      try {
        await expect(f.service.prepare(f.g, f.c.runId)).rejects.toThrow();
        expect(f.effects).toEqual([]);
        expect(
          f.sql
            .prepare(
              "SELECT count(*) n FROM plugin_task_requests WHERE target_id LIKE 'restricted:publication:%'",
            )
            .get(),
        ).toEqual({ n: 0 });
      } finally {
        f.sql.close();
      }
    },
  );
for (const scenario of ['fake-ack', 'revoke-upload', 'wrong-route'])
  it(
    'publication ' + scenario + ' retains UNKNOWN and never authorizes the next effect or retries',
    async () => {
      const f = await fixture(scenario);
      try {
        const a = await f.service.prepare(f.g, f.c.runId);
        await expect(f.service.run(f.g, a.nativeActionId)).rejects.toThrow('UNKNOWN');
        expect((await f.service.record(a.nativeActionId)).state).toBe('UNKNOWN');
        expect(f.effects.length).toBe(scenario === 'revoke-upload' ? 1 : 0);
        if (scenario !== 'revoke-upload')
          expect((await f.service.run(f.g, a.nativeActionId)).state).toBe('HELD');
        expect((await f.service.read(f.g, a.nativeActionId)).publicUrl).toBeNull();
      } finally {
        f.sql.close();
      }
    },
  );
it('guessed action ids, cross-subject read and changed account cannot retrieve authority', async () => {
  const f = await fixture();
  try {
    await expect(f.service.run(f.g, '00000000-0000-0000-0000-000000000000')).rejects.toThrow();
    const a = await f.service.prepare(f.g, f.c.runId);
    await expect(
      f.service.read({ ...f.g, principalId: sha('other') }, a.nativeActionId),
    ).rejects.toThrow('DENIED');
    f.accountChange();
    await expect(f.service.read(f.g, a.nativeActionId)).rejects.toThrow('OWNER_CHANGED');
    expect(f.effects).toHaveLength(0);
  } finally {
    f.sql.close();
  }
});

it('launch default defers restricted publication before approval, rows or remote effects', async () => {
  vi.stubEnv(restrictedPublicationLaunchEnvironment, undefined);
  const f = await fixture();
  try {
    const sourceBefore = JSON.stringify(f.c);
    await expect(f.service.prepare(f.g, f.c.runId)).rejects.toThrow(
      'RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH',
    );
    expect(f.prompts()).toBe(0);
    expect(f.effects).toEqual([]);
    expect(f.sql.prepare("SELECT count(*) n FROM plugin_task_requests WHERE target_id LIKE 'restricted:publication:%'").get()).toEqual({ n: 0 });
    expect(await f.service.lookup(f.g, f.c.runId)).toMatchObject({
      state: 'NOT_OBSERVED',
      publicUrl: null, returnAllowed: false,
    });
    expect(JSON.stringify(f.c)).toBe(sourceBefore);
    await expect(f.service.lookup({ ...f.g, principalId: sha('other') }, f.c.runId)).rejects.toThrow('DENIED');
    f.accountChange();
    await expect(f.service.prepare(f.g, f.c.runId)).rejects.toThrow('OWNER_CHANGED');
  } finally {
    f.sql.close();
  }
});

it('disabling a prepared action preserves it without running, reconciling or releasing its URL', async () => {
  const f = await fixture();
  try {
    const a = await f.service.prepare(f.g, f.c.runId);
    vi.stubEnv(restrictedPublicationLaunchEnvironment, '0');
    await expect(f.service.run(f.g, a.nativeActionId)).rejects.toThrow('RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH');
    await expect(f.service.reconcile(f.g, a.nativeActionId)).rejects.toThrow('RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH');
    expect(await f.service.record(a.nativeActionId)).toEqual(a);
    expect(await f.service.read(f.g, a.nativeActionId)).toMatchObject({
      state: 'PREPARED_NO_REMOTE_EFFECT',
      publicUrl: null, returnAllowed: false, runtimeReady: false,
    });
    expect(f.prompts()).toBe(1);
    expect(f.effects).toEqual([]);
  } finally {
    f.sql.close();
  }
});

it('disabling after a completed publication hides its historical URL and never replays it', async () => {
  const f = await fixture();
  try {
    const a = await f.service.prepare(f.g, f.c.runId);
    await f.service.run(f.g, a.nativeActionId);
    const persisted = await f.service.record(a.nativeActionId);
    vi.stubEnv(restrictedPublicationLaunchEnvironment, 'false');
    expect(await f.service.read(f.g, a.nativeActionId)).toMatchObject({
      state: 'APPLIED_VERIFIED',
      publicUrl: null, returnAllowed: false, runtimeReady: false,
    });
    expect(await f.service.lookup(f.g, f.c.runId)).toMatchObject({ publicUrl: null, returnAllowed: false });
    expect(await f.service.record(a.nativeActionId)).toEqual(persisted);
    await expect(f.service.read({ ...f.g, principalId: sha('other') }, a.nativeActionId)).rejects.toThrow('DENIED');
    vi.stubEnv(restrictedPublicationLaunchEnvironment, 'true');
    expect((await f.service.run(f.g, a.nativeActionId)).state).toBe('HELD');
    expect(f.effects).toHaveLength(3);
  } finally {
    f.sql.close();
  }
});

it('disabling between remote effects retains UNKNOWN and re-enabling never retries the action', async () => {
  const f = await fixture('disable-upload');
  try {
    const a = await f.service.prepare(f.g, f.c.runId);
    await expect(f.service.run(f.g, a.nativeActionId)).rejects.toThrow('UNKNOWN');
    expect((await f.service.record(a.nativeActionId)).state).toBe('UNKNOWN');
    expect(f.effects).toEqual(['remote-staging-prepare']);
    expect(await f.service.read(f.g, a.nativeActionId)).toMatchObject({
      state: 'UNKNOWN', publicUrl: null, returnAllowed: false,
    });
    vi.stubEnv(restrictedPublicationLaunchEnvironment, '1');
    expect((await f.service.run(f.g, a.nativeActionId)).state).toBe('HELD');
    expect(f.effects).toEqual(['remote-staging-prepare']);
  } finally {
    f.sql.close();
  }
});
