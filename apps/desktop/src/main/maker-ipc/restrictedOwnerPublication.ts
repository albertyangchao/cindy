/** Main-owned registration of the user's own iMessage identity. Ordinary grants never imply this role. */
import { createHash, randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import type { DbClient } from '../localDb/client/DbClient.js';
import { pluginTaskRequests } from '../localDb/schema.js';
import type { RestrictedPartnerClaim, RestrictedPartnerGrant } from './restrictedPartnerExecution.js';
import type { NativePublicationRecord, NativePublisherRuntime } from './restrictedPartnerPublication.js';
import { canonical, digest } from './restrictedPublicationProtocol.js';

const key = 'owner:publication:identity';
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const deny: () => never = () => { throw Error('OWNER_PUBLICATION_DENIED'); };
const versions = new WeakMap<object, Map<string, number>>();
const pending = new WeakMap<object, Set<string>>();
type Route = {
  connectionId: string; generation: string; chatId: string; addressHash: string; revision: number;
};
type Registration = {
  schema: 'native-owner-publication-registration/v1';
  pluginId: string; bindingId: string; revision: number; enabled: boolean;
  domainId: string; channelPrincipalId: string; principalId: string; partnerId: string;
  grantId: string; grantRevision: number; approvalRevision: string; dispatchEpoch: number;
  runtimeIdentity: string; publicOrigin: string; sourceRoot: string;
  routes: Route[]; sourceRunId: string; sourceOutputMessageId: string;
  createdAt: number; updatedAt: number;
};
export interface OwnerPublicationIdentityInput {
  action: 'register' | 'revoke'; pluginId: string; principalId: string; domainId: string;
  channelPrincipalId: string; partnerId: string; routes: ReadonlyArray<Route>;
  sourceRunId: string; sourceOutputMessageId: string; sourceText: string;
  publicOrigin: string; runtimeIdentity: string; sourceRoot: string;
  assertCurrent(): void;
}
export type OwnerPublicationPolicy = {
  authorityMode: 'owner-bridge/v1'; ownerBindingRevision: number; ownerBindingSha256: string;
};
type Permit = {
  db: DbClient; pluginId: string; current(): void;
  authorize(g: RestrictedPartnerGrant, runId: string): Promise<OwnerPublicationPolicy>;
};
const permits = new WeakMap<object, Permit>();

/** JSON, copied registration records and a caller's `owner` field cannot stand in for this handle. */
export function assertOwnerPublicationPermitCurrent(handle: object, db: DbClient, pluginId: string) {
  const permit = permits.get(handle);
  if (!permit || permit.db !== db || permit.pluginId !== pluginId) deny();
  permit.current();
}
export async function authorizeOwnerPublication(
  handle: object, db: DbClient, pluginId: string, grant: RestrictedPartnerGrant, runId: string,
  action?: NativePublicationRecord,
) {
  assertOwnerPublicationPermitCurrent(handle, db, pluginId);
  const policy = await permits.get(handle)!.authorize(grant, runId);
  assertOwnerPublicationPermitCurrent(handle, db, pluginId);
  if (action && (action.authorityMode !== policy.authorityMode ||
      action.ownerBindingRevision !== policy.ownerBindingRevision ||
      action.ownerBindingSha256 !== policy.ownerBindingSha256)) deny();
  return policy;
}

/** Existing account DB and exact-row CAS: no new migration, settings file or plugin-writable role. */
export function createOwnerPublicationRegistration(
  db: DbClient, pluginId: string, readOwner: () => void,
  current: (grant: RestrictedPartnerGrant) => void,
  ports: {
    readGrant(id: string): Promise<RestrictedPartnerGrant | undefined>;
    readRun(id: string): Promise<RestrictedPartnerClaim | undefined>;
    confirm(input: OwnerPublicationIdentityInput): Promise<boolean>;
    runtime(): NativePublisherRuntime | undefined;
    now?: () => number;
  },
) {
  const now = ports.now ?? Date.now;
  let generations = versions.get(db);
  if (!generations) { generations = new Map(); versions.set(db, generations); }
  const version = () => generations!.get(pluginId) ?? 0;
  const invalidate = () => generations!.set(pluginId, version() + 1);
  const rowId = 'owner-publication-registration:' + hash(pluginId);
  const read = async () => {
    readOwner();
    const [row] = await db.drizzle.select().from(pluginTaskRequests).where(and(
      eq(pluginTaskRequests.pluginId, pluginId), eq(pluginTaskRequests.targetId, key),
    )).limit(1);
    readOwner();
    if (!row) return undefined;
    let value: Registration;
    try { value = JSON.parse(row.payload); } catch { return deny(); }
    if (!value || value.schema !== 'native-owner-publication-registration/v1' ||
        row.id !== rowId || row.operation !== 'target' || row.requestKey !== key ||
        value.pluginId !== pluginId || row.fingerprint !== digest(value) ||
        value.revision !== row.revision || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
        typeof value.enabled !== 'boolean' || !/^[a-f0-9-]{36}$/.test(value.bindingId) ||
        !Array.isArray(value.routes) || !value.routes.length || value.routes.length > 16 ||
        !Number.isSafeInteger(value.grantRevision) || value.grantRevision < 1 ||
        !Number.isSafeInteger(value.dispatchEpoch) || value.dispatchEpoch < 1 ||
        [value.principalId, value.grantId, value.runtimeIdentity].some(x => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x)) ||
        [value.domainId, value.channelPrincipalId, value.partnerId, value.approvalRevision,
          value.sourceRunId, value.sourceOutputMessageId, value.sourceRoot, value.publicOrigin]
          .some(x => typeof x !== 'string' || !x || x.length > 4096) ||
        hash(JSON.stringify([value.domainId, value.channelPrincipalId])) !== value.principalId ||
        !Number.isSafeInteger(value.createdAt) || !Number.isSafeInteger(value.updatedAt) ||
        value.createdAt > value.updatedAt || value.createdAt < 0 ||
        value.routes.some(route => !validRoute(route)) ||
        new Set(value.routes.map(route => canonical(route))).size !== value.routes.length) deny();
    return value;
  };
  const source = async (g: RestrictedPartnerGrant, runId: string) => {
    current(g);
    const fresh = await ports.readGrant(g.id);
    current(g);
    if (canonical(fresh) !== canonical(g) || !g.enabled || !g.dispatchEnabled || g.pluginId !== pluginId) deny();
    const claim = await ports.readRun(runId);
    current(g);
    if (!claim || claim.state !== 'COMPLETE' || claim.pluginId !== pluginId || claim.grantId !== g.id ||
        claim.grantRevision !== g.revision || claim.principalId !== g.principalId ||
        claim.partnerId !== g.partnerId || !claim.output || !claim.outputMessageId ||
        !claim.nativeThreadId || !claim.laneSessionId || !claim.channel ||
        claim.channel.epoch !== g.dispatchEpoch ||
        hash(JSON.stringify([claim.channel.domainId, claim.channel.principalId])) !== g.principalId ||
        !validRoute(routeOf(claim))) deny();
    return claim;
  };
  const subjectMatches = (r: Registration, g: RestrictedPartnerGrant, c: RestrictedPartnerClaim) =>
    Boolean(r.enabled && r.principalId === g.principalId &&
      r.domainId === c.channel!.domainId && r.channelPrincipalId === c.channel!.principalId &&
      r.grantId === g.id && r.grantRevision === g.revision && r.partnerId === g.partnerId &&
      r.approvalRevision === g.approvalRevision && r.dispatchEpoch === g.dispatchEpoch &&
      r.routes.some(route => canonical(route) === canonical(routeOf(c))));
  const matches = (r: Registration, g: RestrictedPartnerGrant, c: RestrictedPartnerClaim) => {
    const runtime = ports.runtime();
    return Boolean(runtime && subjectMatches(r, g, c) &&
      r.runtimeIdentity === runtime.identity && r.publicOrigin === runtime.publicOrigin &&
      r.sourceRoot === runtime.sourceRoot);
  };
  const authorize = async (g: RestrictedPartnerGrant, runId: string): Promise<OwnerPublicationPolicy> => {
    const c = await source(g, runId), r = await read();
    current(g);
    if (!r || !matches(r, g, c)) deny();
    return { authorityMode: 'owner-bridge/v1', ownerBindingRevision: r.revision, ownerBindingSha256: digest(r) };
  };
  const summary = async (g: RestrictedPartnerGrant, runId: string) => {
    const c = await source(g, runId), r = await read(), runtime = ports.runtime();
    current(g);
    let configured = false;
    if (runtime) {
      try { await runtime.verify(); configured = true; } catch { /* No setup or source mismatch grants authority. */ }
      current(g);
    }
    const bound = Boolean(r && subjectMatches(r, g, c));
    const eligible = Boolean(r && matches(r, g, c) && configured);
    return { version: 1, configured, bound, eligible, bindingRevision: r?.revision ?? null,
      authority: eligible ? 'native-owner-bridge/v1' : false };
  };
  const write = async (old: Registration | undefined, next: Registration,
    g?: RestrictedPartnerGrant, c?: RestrictedPartnerClaim) => {
    readOwner();
    if (g) current(g);
    const guards = g && c ? ` AND EXISTS(SELECT 1 FROM plugin_task_requests WHERE plugin_id=? AND operation='target' AND target_id=? AND payload=?) AND EXISTS(SELECT 1 FROM plugin_task_requests WHERE plugin_id=? AND operation='target' AND target_id=? AND payload=?)` : '';
    const args = g && c ? [pluginId, 'restricted:grant:' + g.id, JSON.stringify(g),
      pluginId, 'restricted:input:' + c.inputId, JSON.stringify(c)] : [];
    const raw = JSON.stringify(next);
    const result = old
      ? await db.exec(`UPDATE plugin_task_requests SET payload=?,fingerprint=?,revision=? WHERE id=? AND plugin_id=? AND operation='target' AND payload=? AND revision=?${guards}`,
        [raw, digest(next), next.revision, rowId, pluginId, JSON.stringify(old), old.revision, ...args])
      : await db.exec(`INSERT INTO plugin_task_requests(id,plugin_id,operation,target_id,request_key,fingerprint,payload,revision,created_at) SELECT ?,?,'target',?,?,?,?,1,? WHERE 1=1${guards} ON CONFLICT DO NOTHING`,
        [rowId, pluginId, key, key, digest(next), raw, next.createdAt, ...args]);
    readOwner();
    if (g) current(g);
    if (result.changes !== 1) throw Error('OWNER_PUBLICATION_CONFLICT');
    const after = await read();
    if (canonical(after) !== canonical(next)) throw Error('OWNER_PUBLICATION_CONFLICT');
    return next;
  };
  const exclusive = async <T>(operation: () => Promise<T>) => {
    let locks = pending.get(db);
    if (!locks) { locks = new Set(); pending.set(db, locks); }
    if (locks.has(pluginId)) throw Error('OWNER_PUBLICATION_PENDING');
    locks.add(pluginId);
    invalidate(); // Invalidate in-flight effects before a registration or revocation dialog can await.
    try { return await operation(); } finally { locks.delete(pluginId); }
  };
  return {
    status: summary,
    async register(g: RestrictedPartnerGrant, runId: string) {
      return exclusive(async () => {
        const c = await source(g, runId), old = await read(), runtime = ports.runtime();
        current(g);
        if (!runtime || !runtime.sourceRoot || !/^[a-f0-9]{64}$/.test(runtime.identity))
          throw Error('NATIVE_PUBLICATION_RUNTIME_UNAVAILABLE');
        if (old?.enabled && old.principalId !== g.principalId) throw Error('OWNER_PUBLICATION_IDENTITY_CONFLICT');
        await runtime.verify();
        current(g);
        const route = routeOf(c);
        const keepRoutes = old && old.principalId === g.principalId && old.enabled &&
          old.grantId === g.id && old.grantRevision === g.revision && old.dispatchEpoch === g.dispatchEpoch &&
          old.runtimeIdentity === runtime.identity ? old.routes : [];
        const routes = [...keepRoutes.filter(value => canonical(value) !== canonical(route)), route];
        if (routes.length > 16) deny();
        const time = now();
        const next: Registration = {
          schema: 'native-owner-publication-registration/v1', pluginId,
          bindingId: old?.bindingId ?? randomUUID(), revision: (old?.revision ?? 0) + 1, enabled: true,
          domainId: c.channel!.domainId, channelPrincipalId: c.channel!.principalId,
          principalId: g.principalId, partnerId: g.partnerId, grantId: g.id, grantRevision: g.revision,
          approvalRevision: g.approvalRevision, dispatchEpoch: g.dispatchEpoch,
          runtimeIdentity: runtime.identity, publicOrigin: runtime.publicOrigin, sourceRoot: runtime.sourceRoot,
          routes, sourceRunId: runId, sourceOutputMessageId: c.outputMessageId!,
          createdAt: old?.createdAt ?? time, updatedAt: time,
        };
        const approved = await ports.confirm({ ...next, action: 'register',
          sourceText: c.inputText ?? '', assertCurrent: () => current(g) });
        current(g);
        if (!approved) deny();
        const fresh = await source(g, runId);
        if (canonical(fresh) !== canonical(c) || canonical(await read()) !== canonical(old) ||
            ports.runtime() !== runtime) deny();
        await runtime.verify();
        current(g);
        await write(old, next, g, c);
        return { ...(await summary(g, runId)), registered: true };
      });
    },
    async revoke(g: RestrictedPartnerGrant) {
      return exclusive(async () => {
        readOwner();
        const old = await read();
        if (!old) return { revoked: true, bindingRevision: null, unknownPreserved: true };
        if (old.principalId !== g.principalId || old.grantId !== g.id) deny();
        if (!old.enabled) return { revoked: true, bindingRevision: old.revision, unknownPreserved: true };
        if (!(await ports.confirm({ ...old, action: 'revoke', sourceText: '', assertCurrent: readOwner }))) deny();
        readOwner();
        const next = await write(old, { ...old, enabled: false, revision: old.revision + 1, updatedAt: now() });
        return { revoked: true, bindingRevision: next.revision, unknownPreserved: true };
      });
    },
    permit() {
      readOwner();
      const captured = version(), handle = Object.freeze({});
      permits.set(handle, { db, pluginId, authorize, current: () => {
        readOwner();
        if (captured !== version() || pending.get(db)?.has(pluginId)) deny();
      } });
      return handle;
    },
  };
}
function routeOf(claim: RestrictedPartnerClaim): Route {
  const c = claim.channel;
  if (!c) return deny();
  return { connectionId: c.connectionId, generation: c.generation, chatId: c.chatId,
    addressHash: c.addressHash ?? '', revision: c.revision };
}
function validRoute(route: Route) {
  return route && Object.keys(route).sort().join(',') === 'addressHash,chatId,connectionId,generation,revision' &&
    [route.connectionId, route.generation, route.chatId].every(x => typeof x === 'string' && x.length > 0 && x.length <= 256) &&
    typeof route.addressHash === 'string' && /^[a-f0-9]{64}$/.test(route.addressHash) &&
    Number.isSafeInteger(route.revision) && route.revision > 0;
}
