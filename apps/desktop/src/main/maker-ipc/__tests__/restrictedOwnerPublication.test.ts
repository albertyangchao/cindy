import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { createHash } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import type { DbClient } from '../../localDb/client/DbClient.js';
import type { RestrictedPartnerClaim, RestrictedPartnerGrant } from '../restrictedPartnerExecution.js';
import { createRestrictedPartnerStore } from '../restrictedPartnerStore.js';
import { createOwnerPublicationRegistration } from '../restrictedOwnerPublication.js';
import { approveOwnerPublicationIdentity } from '../restrictedOwnerPublicationApproval.js';
import { approveNativePublicRelease } from '../restrictedPublicationApproval.js';
import { createNativePublicationAuthority, createOwnerBridgePublicationAuthority, publicationSha,
  type NativePublicationRecord, type NativePublicationReceipt, type NativePublisherRuntime } from '../restrictedPartnerPublication.js';
import { releaseId, wireBinding } from '../restrictedPublicationProtocol.js';
import { restrictedPublicationLaunchEnvironment } from '../restrictedPublicationLaunch.js';

// Unit tier: D2 must cross a persisted, owner-approved identity boundary before the real action
// state machine can dispatch. Existing restricted publication tests only cover its full gate.
// SQLite and Host authority are real; native dialog decisions and remote effects are the I/O seams.
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const databases: Database.Database[] = [];
afterEach(() => { for (const db of databases.splice(0)) db.close(); vi.unstubAllEnvs(); });
async function fixture() {
  vi.stubEnv(restrictedPublicationLaunchEnvironment, undefined);
  const sql = new Database(':memory:'); databases.push(sql);
  sql.exec('CREATE TABLE plugin_task_requests(id TEXT PRIMARY KEY,plugin_id TEXT,operation TEXT,target_id TEXT,request_key TEXT,fingerprint TEXT,payload TEXT,revision INTEGER,created_at INTEGER,UNIQUE(plugin_id,operation,target_id,request_key));');
  const db = { drizzle: drizzle(sql), exec: async (query: string, params: unknown[]) =>
    ({ changes: sql.prepare(query).run(...params).changes }) } as unknown as DbClient;
  let owner = true, active = true, trusted = true, checked = true;
  const read = () => { if (!owner) throw Error('OWNER_CHANGED'); };
  const current = () => { read(); if (!active) throw Error('REVOKED'); };
  const store = createRestrictedPartnerStore(db, read);
  const g: RestrictedPartnerGrant = { version: 1, id: sha('owner grant'), revision: 1,
    pluginId: 'synthetic-plugin', principalId: sha(JSON.stringify(['domain', 'owner-subject'])),
    partnerId: 'synthetic-partner', enabled: true, personaSha256: sha('persona'),
    resourceIds: [], resources: [], approvalRevision: 'approved-install', dispatchEpoch: 2, dispatchEnabled: true };
  await store.compareAndSwapGrant(g, 0);
  const c: RestrictedPartnerClaim = { version: 1, runId: 'native-owner-run', inputId: 'input',
    pluginId: g.pluginId, principalId: g.principalId, partnerId: g.partnerId,
    grantId: g.id, grantRevision: g.revision, inputSha256: sha('original-input'), state: 'COMPLETE',
    nativeThreadId: 'native-thread', outputMessageId: 'output-message', output: 'A synthetic public report.',
    inputText: 'Create a synthetic public report.', laneSessionId: 'original-lane',
    channel: { domainId: 'domain', principalId: 'owner-subject', connectionId: 'connection',
      generation: 'generation', chatId: 'original-chat', eventId: 'original-event', revision: 3,
      epoch: g.dispatchEpoch, addressHash: sha('synthetic-address') } };
  const persist = (claim = c) => {
    sql.prepare("INSERT OR REPLACE INTO plugin_task_requests VALUES(?,?,'target',?,?,?,?,4,?)")
      .run('restricted-run:' + claim.runId, g.pluginId, 'restricted:input:' + claim.inputId,
        claim.inputId, claim.inputSha256, JSON.stringify(claim), Date.now());
  };
  persist();
  const effects: string[] = [];
  let stage: NativePublicationRecord | undefined;
  let afterEffect: (() => Promise<void>) | undefined;
  let afterApproval: (() => void) | undefined;
  const dialogs: string[] = [];
  const makeReceipt = (a: NativePublicationRecord) => {
    const value: Omit<NativePublicationReceipt, 'receiptSha256'> = {
      schema: 'bridge-native-html-release/v1', nativeActionId: a.nativeActionId, actionRevision: a.actionRevision,
      grantId: a.grantId, grantRevision: a.grantRevision, completedOutputSha256: a.completedOutputSha256,
      artifactSha256: a.artifactSha256!, publisherBindingSha256: a.publisherBindingSha256!,
      artifactRelative: a.artifactRelative, dispatcher: 'scripts.publish_generic_html_direct',
      delivery_state: 'applied', remoteReleaseId: releaseId(wireBinding(a)), verifiedSha256: a.artifactSha256,
      public_url_verified: true, observedAt: new Date().toISOString(),
    };
    return { ...value, receiptSha256: publicationSha(value) };
  };
  const runtime: NativePublisherRuntime = {
    identity: sha('reviewed-owner-runtime'), sourceRoot: '/synthetic/reviewed-bridge',
    publicOrigin: 'https://reports.example.invalid', dispatcher: 'scripts.publish_generic_html_direct',
    verify: async () => {},
    inspect: async a => ({ artifactSha256: sha('rendered-html'), publisherBindingSha256: sha('publisher-binding'),
      completedOutputSha256: a.completedOutputSha256, artifactRelative: a.artifactRelative }),
    stage: async (_a, _text, control) => { stage = await control.stageBind(); },
    apply: async (_a, control) => {
      await control.beforeEffect('remote-staging-prepare');
      await afterEffect?.();
      await control.beforeEffect('remote-staging-upload');
      await control.beforeEffect('remote-transaction');
      const value = await service.record(stage!.nativeActionId);
      return makeReceipt(value);
    },
    dispatch: async (_a, effect) => { effects.push(effect); },
    reconcile: async a => makeReceipt(a),
  };
  let configured: NativePublisherRuntime | undefined = runtime;
  const ports = { readGrant: (id: string) => store.readGrant(g.pluginId, id),
    readRun: (id: string) => store.byRun(g.pluginId, id), runtime: () => configured };
  const native = { window: () => ({ isDestroyed: () => false }) as any, trusted: () => trusted,
    show: async (_window: unknown, options: any) => {
      dialogs.push(options.title);
      expect(options.defaultId).toBe(0);
      expect(options.detail).toContain(runtime.identity);
      expect(options.detail).toContain(runtime.sourceRoot);
      return { response: 1, checkboxChecked: checked };
    } };
  const registration = createOwnerPublicationRegistration(db, g.pluginId, read, current,
    { ...ports, confirm: input => approveOwnerPublicationIdentity(input, { ...native, text: key => key }) });
  const approve = async (input: Parameters<typeof approveNativePublicRelease>[0]) => {
    const result = await approveNativePublicRelease(input, native);
    afterApproval?.();
    return result;
  };
  const createService = () => createOwnerBridgePublicationAuthority(db, g.pluginId, read, current,
    { ...ports, approve }, registration.permit());
  let service = createService();
  return { sql, db, g, c, persist, ports, current, read, registration, runtime, effects, dialogs,
    get service() { return service; }, freshService: () => { service = createService(); return service; },
    register: async () => { const result = await registration.register(g, c.runId); service = createService(); return result; },
    native, setTrusted: (value: boolean) => { trusted = value; }, setChecked: (value: boolean) => { checked = value; },
    disable: () => { active = false; }, accountChange: () => { owner = false; },
    unconfigure: () => { configured = undefined; }, afterEffect: (fn: () => Promise<void>) => { afterEffect = fn; },
    afterApproval: (fn: () => void) => { afterApproval = fn; } };
}

it('only native identity approval unlocks D2; exact final artifact stays approved with the full gate off', async () => {
  const f = await fixture();
  expect(await f.registration.status(f.g, f.c.runId)).toEqual({ version: 1, configured: true,
    bound: false, eligible: false, bindingRevision: null, authority: false });
  await expect(f.service.prepare(f.g, f.c.runId)).rejects.toThrow('OWNER_PUBLICATION_DENIED');
  expect(f.dialogs).toEqual([]);
  expect(await f.register()).toMatchObject({ bound: true, eligible: true, registered: true, bindingRevision: 1 });
  const prepared = await f.service.prepare(f.g, f.c.runId);
  expect(prepared).toMatchObject({ authorityMode: 'owner-bridge/v1', ownerBindingRevision: 1,
    runId: f.c.runId, chatId: f.c.channel!.chatId, eventId: f.c.channel!.eventId, principalId: f.g.principalId });
  await f.service.run(f.g, prepared.nativeActionId);
  expect(await f.service.read(f.g, prepared.nativeActionId)).toMatchObject({ state: 'APPLIED_VERIFIED', returnAllowed: true });
  expect(f.effects).toEqual(['remote-staging-prepare', 'remote-staging-upload', 'remote-transaction']);
  expect(f.dialogs).toHaveLength(3);
  const old = createNativePublicationAuthority(f.db, f.g.pluginId, f.read, f.current,
    { ...f.ports, approve: async () => ({ approved: true, publicNonPersonal: true }) });
  await expect(old.prepare(f.g, f.c.runId)).rejects.toThrow('RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH');
  await expect(old.read(f.g, prepared.nativeActionId)).rejects.toThrow('NATIVE_PUBLIC_RELEASE_DENIED');
});

it.each(['untrusted', 'unchecked'] as const)('does not persist a role from %s native identity confirmation', async kind => {
  const f = await fixture();
  if (kind === 'untrusted') f.setTrusted(false); else f.setChecked(false);
  await expect(f.register()).rejects.toThrow('OWNER_PUBLICATION_DENIED');
  expect(await f.registration.status(f.g, f.c.runId)).toMatchObject({ bound: false, eligible: false });
  expect(f.effects).toEqual([]);
});

it.each(['UNKNOWN', 'missing-address', 'wrong-principal'] as const)('cannot register %s source or manufacture a permit from JSON', async kind => {
  const f = await fixture();
  if (kind === 'UNKNOWN') f.c.state = 'UNKNOWN';
  if (kind === 'missing-address') delete f.c.channel!.addressHash;
  if (kind === 'wrong-principal') f.c.channel!.principalId = 'other-subject';
  f.persist();
  await expect(f.register()).rejects.toThrow('OWNER_PUBLICATION_DENIED');
  expect(() => createOwnerBridgePublicationAuthority(f.db, f.g.pluginId, f.read, f.current,
    { ...f.ports, approve: async () => ({ approved: true, publicNonPersonal: true }) }, {}))
    .toThrow('OWNER_PUBLICATION_DENIED');
  expect(f.dialogs).toEqual([]);
});

it('requires separate native confirmation of an alias and invalidates previously prepared actions when registration changes', async () => {
  const f = await fixture(); await f.register();
  const action = await f.service.prepare(f.g, f.c.runId);
  const alias = structuredClone(f.c);
  Object.assign(alias, { runId: 'native-alias-run', inputId: 'alias-input', outputMessageId: 'alias-output' });
  Object.assign(alias.channel!, { chatId: 'alias-chat', addressHash: sha('second-synthetic-address'), eventId: 'alias-event' });
  f.persist(alias);
  expect(await f.registration.status(f.g, alias.runId)).toMatchObject({ bound: false, eligible: false });
  await f.registration.register(f.g, alias.runId);
  expect(await f.registration.status(f.g, alias.runId)).toMatchObject({ bound: true, eligible: true });
  await expect(f.service.run(f.g, action.nativeActionId)).rejects.toThrow('OWNER_PUBLICATION_DENIED');
  expect(await f.freshService().read(f.g, action.nativeActionId)).toMatchObject({ returnAllowed: false, publicUrl: null });
  expect(f.effects).toEqual([]);
});

it.each(['unconfigured', 'source-replaced'] as const)('keeps identity bound but refuses publication after %s runtime', async kind => {
  const f = await fixture(); await f.register();
  const action = await f.service.prepare(f.g, f.c.runId);
  if (kind === 'unconfigured') f.unconfigure(); else f.runtime.identity = sha('changed-source');
  expect(await f.registration.status(f.g, f.c.runId)).toMatchObject({ bound: true, eligible: false, authority: false });
  await expect(f.service.run(f.g, action.nativeActionId)).rejects.toThrow('OWNER_PUBLICATION_DENIED');
  expect(f.effects).toEqual([]);
});

it('a revoke during dispatch retains UNKNOWN and cannot replay or return a URL', async () => {
  const f = await fixture(); await f.register();
  const action = await f.service.prepare(f.g, f.c.runId);
  f.afterEffect(async () => { await f.registration.revoke(f.g); });
  await expect(f.service.run(f.g, action.nativeActionId)).rejects.toThrow('NATIVE_PUBLICATION_UNKNOWN');
  expect(f.effects).toEqual(['remote-staging-prepare']);
  expect(await f.freshService().read(f.g, action.nativeActionId)).toMatchObject({ state: 'UNKNOWN', returnAllowed: false, publicUrl: null });
  await expect(f.service.run(f.g, action.nativeActionId)).rejects.toThrow('OWNER_PUBLICATION_DENIED');
  expect(f.effects).toEqual(['remote-staging-prepare']);
});

it('an output changed while native approval waits cannot be persisted as approved content', async () => {
  const f = await fixture(); await f.register();
  f.afterApproval(() => { f.c.output = 'Changed output'; f.persist(); });
  await expect(f.service.prepare(f.g, f.c.runId)).rejects.toThrow('NATIVE_PUBLIC_RELEASE_DENIED');
  expect(f.sql.prepare("SELECT count(*) AS n FROM plugin_task_requests WHERE id LIKE 'native-publication:%'").get()).toEqual({ n: 0 });
  expect(f.effects).toEqual([]);
});

it('revocation after verified publication retains historical effect metadata but removes return authority', async () => {
  const f = await fixture(); await f.register();
  const action = await f.service.prepare(f.g, f.c.runId);
  await f.service.run(f.g, action.nativeActionId);
  await f.registration.revoke(f.g);
  expect(await f.freshService().read(f.g, action.nativeActionId)).toMatchObject({ state: 'APPLIED_VERIFIED', returnAllowed: false, publicUrl: null });
  expect(await f.registration.status(f.g, f.c.runId)).toMatchObject({ bound: false, eligible: false, bindingRevision: 2 });
});

it('account invalidation while the native identity dialog awaits prevents a durable registration', async () => {
  const f = await fixture();
  const registry = createOwnerPublicationRegistration(f.db, f.g.pluginId, f.read, f.current,
    { ...f.ports, confirm: async input => { input.assertCurrent(); f.accountChange(); return true; } });
  await expect(registry.register(f.g, f.c.runId)).rejects.toThrow('OWNER_CHANGED');
  expect(f.sql.prepare("SELECT count(*) AS n FROM plugin_task_requests WHERE id LIKE 'owner-publication-registration:%'").get()).toEqual({ n: 0 });
});
