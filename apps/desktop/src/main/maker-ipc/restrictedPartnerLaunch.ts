import { createHash, randomUUID } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import type { DbClient } from '../localDb/client/DbClient.js';
import { pluginTaskRequests as table } from '../localDb/schema.js';
import type { RestrictedPartnerGrant, RestrictedPartnerClaim } from './restrictedPartnerExecution.js';

type Route = {
  domainId: string; principalId: string; connectionId: string; generation: string;
  addressHash: string; inputs: Array<{ inputId: string; eventId: string; chatId: string }>;
};
type Row = typeof table.$inferSelect;
type RecordFact = { inputId: string; runId: string; routeHash: string; eventId: string; chatId: string };
type Source = {
  db: DbClient; grant: string; routes: Route[]; rows: Row[]; held: Set<string>;
  facts: { version: 1; snapshotId: string; sha256: string; records: RecordFact[]; unresolvedCount: number };
  createdAt: number; used: boolean;
};
const sources = new WeakMap<object, Source>();
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const hex = (x: unknown): x is string => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const id = (x: unknown): x is string => typeof x === 'string' && x.length > 0 && x.length <= 256;
const deny: () => never = (): never => { throw Error('RESTRICTED_PARTNER_LAUNCH_UNPROVEN'); };
const columns = (rows: Row[]) => JSON.stringify(rows.map(r => [
  r.id, r.pluginId, r.operation, r.targetId, r.requestKey, r.fingerprint, r.payload, r.revision, r.createdAt,
]));

function routesFor(grant: RestrictedPartnerGrant, raw: unknown): Route[] {
  if (!Array.isArray(raw) || !raw.length || raw.length > 2 || !grant.requirements) deny();
  const routes = raw as Route[];
  for (const r of routes) {
    if (!r || Object.keys(r).sort().join() !== 'addressHash,connectionId,domainId,generation,inputs,principalId' ||
        ![r.domainId,r.principalId,r.connectionId,r.generation].every(id) || !hex(r.addressHash) ||
        sha(JSON.stringify([r.domainId,r.principalId])) !== grant.principalId ||
        !grant.requirements!.addressHashes.includes(r.addressHash) || !Array.isArray(r.inputs) || r.inputs.length > 4000)
      deny();
    for (const input of r.inputs)
      if (!input || Object.keys(input).sort().join() !== 'chatId,eventId,inputId' ||
          !hex(input.inputId) || !id(input.eventId) || !id(input.chatId) ||
          sha(JSON.stringify([r.connectionId,r.generation,input.eventId])) !== input.inputId) deny();
  }
  if (new Set(routes.map(r => r.addressHash)).size !== routes.length ||
      grant.requirements!.addressHashes.length !== routes.length) deny();
  return structuredClone(routes);
}

async function originalRows(db: DbClient, grant: RestrictedPartnerGrant, routes: Route[], current: () => void) {
  current();
  // A malformed source cannot disappear behind json_extract or a caller count.
  const rows = await db.drizzle.select().from(table).where(and(
    eq(table.pluginId, grant.pluginId),
    sql`(${table.targetId} LIKE 'restricted:input:%' OR ${table.id} LIKE 'restricted-run:%')`,
    sql`CASE WHEN json_valid(${table.payload}) THEN coalesce(json_extract(${table.payload},'$.state'),'UNKNOWN') <> 'COMPLETE' ELSE 1 END`,
  )).orderBy(table.id).limit(4001);
  current();
  if (rows.length > 4000) throw Error('RESTRICTED_PARTNER_LAUNCH_LIMIT');
  const heldRows = await db.drizzle.select().from(table).where(and(eq(table.pluginId, grant.pluginId),
    eq(table.operation, 'target'), sql`${table.targetId} LIKE 'restricted:launch-held:%'`));
  current();
  const selected: Row[] = [], facts: RecordFact[] = [], held = new Set<string>();
  for (const row of rows) {
    let claim: RestrictedPartnerClaim;
    try { claim = JSON.parse(row.payload); } catch { deny(); }
    if (!claim! || claim!.version !== 1 || claim!.state !== 'UNKNOWN' || claim!.pluginId !== grant.pluginId ||
        !id(claim!.principalId) || !id(claim!.inputId) || !id(claim!.runId) || !hex(claim!.inputSha256) ||
        row.operation !== 'target' || row.id !== 'restricted-run:' + claim!.runId ||
        row.targetId !== 'restricted:input:' + claim!.inputId || row.requestKey !== claim!.inputId ||
        row.fingerprint !== claim!.inputSha256) deny();
    if (claim!.principalId !== grant.principalId) continue;
    const c = claim!.channel;
    if (!c || !Number.isSafeInteger(c.epoch) || c.epoch < 1 ||
        !Number.isSafeInteger(c.revision) || c.revision < 1 || !id(c.chatId) || !id(c.eventId) ||
        sha(JSON.stringify([c.connectionId,c.generation,c.eventId])) !== claim!.inputId) deny();
    const matches = routes.filter(r => r.domainId === c!.domainId && r.principalId === c!.principalId &&
      r.connectionId === c!.connectionId && r.generation === c!.generation &&
      (c!.addressHash === undefined || c!.addressHash === r.addressHash) &&
      r.inputs.some(i => i.inputId === claim!.inputId && i.eventId === c!.eventId && i.chatId === c!.chatId));
    if (matches.length !== 1) deny();
    const receipt = heldRows.find(h => h.targetId === 'restricted:launch-held:' + claim!.inputId);
    if (receipt) {
      let value: Record<string, unknown>;
      try { value = JSON.parse(receipt.payload); } catch { deny(); }
      if (value!.schema !== 'restricted-native-launch-hold/v1' || value!.sourcePayload !== row.payload ||
          value!.sourceRevision !== row.revision || value!.sourceCreatedAt !== row.createdAt || value!.principalId !== grant.principalId ||
          value!.inputId !== claim!.inputId || value!.sourceId !== row.id) deny();
      held.add(row.id);
    } else if (claim!.grantId !== grant.id || claim!.grantRevision !== grant.revision ||
        claim!.partnerId !== grant.partnerId || c.epoch > grant.dispatchEpoch) deny();
    selected.push(row);
    facts.push({ inputId: claim!.inputId, runId: claim!.runId, routeHash: matches[0]!.addressHash,
      eventId: c.eventId, chatId: c.chatId });
  }
  return { rows: selected, facts, held };
}

/** The caller gets a projection; the original rows and authority stay in Main. */
export async function captureRestrictedPartnerLaunch(db: DbClient, grant: RestrictedPartnerGrant,
  rawRoutes: unknown, current: () => void) {
  const routes = routesFor(grant, rawRoutes), result = await originalRows(db, grant, routes, current);
  const facts = { version: 1 as const, snapshotId: randomUUID(), sha256: sha(columns(result.rows)),
    records: result.facts, unresolvedCount: result.rows.length };
  const handle = Object.freeze({});
  sources.set(handle, { db, grant: JSON.stringify(grant), routes, rows: result.rows, held: result.held,
    facts, createdAt: Date.now(), used: false });
  return { handle, facts: structuredClone(facts) };
}

export async function refreshRestrictedPartnerLaunch(handle: object, db: DbClient,
  grant: RestrictedPartnerGrant, rawRoutes: unknown, current: () => void) {
  const source = sources.get(handle);
  if (!source || source.db !== db || source.used || source.grant !== JSON.stringify(grant) ||
      Date.now() < source.createdAt || Date.now() - source.createdAt > 300_000 ||
      JSON.stringify(routesFor(grant, rawRoutes)) !== JSON.stringify(source.routes)) deny();
  const now = await originalRows(db, grant, source!.routes, current);
  if (columns(now.rows) !== columns(source!.rows) || JSON.stringify([...now.held]) !== JSON.stringify([...source!.held])) deny();
  return structuredClone(source!.facts);
}

/** Called only after the same Host instance invalidates and fences the grant. */
export async function holdRestrictedPartnerLaunch(handle: object, db: DbClient,
  before: RestrictedPartnerGrant, fenced: RestrictedPartnerGrant, operationId: string, current: () => void) {
  const source = sources.get(handle);
  if (!source || source.db !== db || source.used || source.grant !== JSON.stringify(before) ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(operationId) ||
      JSON.stringify({ ...fenced, dispatchEpoch: before.dispatchEpoch, dispatchEnabled: before.dispatchEnabled }) !== source.grant ||
      fenced.dispatchEnabled || fenced.dispatchEpoch !== before.dispatchEpoch + 1) deny();
  source!.used = true; // A lost ACK is not permission to issue another effect.
  const now = await originalRows(db, before, source!.routes, current);
  if (columns(now.rows) !== columns(source!.rows)) deny();
  const pending = source!.rows.filter(r => !source!.held.has(r.id));
  const records = pending.map(row => {
    const claim = JSON.parse(row.payload) as RestrictedPartnerClaim;
    const payload = JSON.stringify({ schema: 'restricted-native-launch-hold/v1', operationId,
      snapshotId: source!.facts.snapshotId, sourceId: row.id, sourcePayload: row.payload,
      sourceRevision: row.revision, sourceCreatedAt: row.createdAt, inputId: claim.inputId, principalId: claim.principalId,
      eventId: claim.channel!.eventId, connectionId: claim.channel!.connectionId,
      fencedEpoch: fenced.dispatchEpoch });
    return { id: 'restricted-launch-held:' + claim.runId, targetId: 'restricted:launch-held:' + claim.inputId,
      requestKey: claim.inputId, fingerprint: sha(payload), payload };
  });
  current();
  // One guarded INSERT keeps the source set all-or-none. The UNKNOWN source
  // payloads remain byte-for-byte unchanged in their original table rows.
  if (records.length) {
    const result = await db.exec(`INSERT INTO plugin_task_requests
      (id,plugin_id,operation,target_id,request_key,fingerprint,payload,revision,created_at)
      SELECT json_extract(j.value,'$.id'),?,'target',json_extract(j.value,'$.targetId'),
        json_extract(j.value,'$.requestKey'),json_extract(j.value,'$.fingerprint'),json_extract(j.value,'$.payload'),1,?
      FROM json_each(?) j
      WHERE EXISTS (SELECT 1 FROM plugin_task_requests g WHERE g.plugin_id=? AND g.operation='target'
        AND g.target_id=? AND g.payload=?)
      AND NOT EXISTS (SELECT 1 FROM json_each(?) s LEFT JOIN plugin_task_requests r
        ON r.id=json_extract(s.value,'$.id') AND r.plugin_id=? AND r.operation='target'
        WHERE r.id IS NULL OR r.payload IS NOT json_extract(s.value,'$.payload')
          OR r.revision IS NOT json_extract(s.value,'$.revision') OR r.created_at IS NOT json_extract(s.value,'$.createdAt')
          OR r.target_id IS NOT json_extract(s.value,'$.targetId') OR r.request_key IS NOT json_extract(s.value,'$.requestKey')
          OR r.fingerprint IS NOT json_extract(s.value,'$.fingerprint'))
      AND (SELECT count(*) FROM plugin_task_requests r WHERE r.plugin_id=? AND r.operation='target'
        AND r.target_id LIKE 'restricted:input:%' AND json_extract(r.payload,'$.principalId')=?
        AND coalesce(json_extract(r.payload,'$.state'),'UNKNOWN')<>'COMPLETE')=?`,
      [before.pluginId,Date.now(),JSON.stringify(records),before.pluginId,'restricted:grant:'+before.id,
        JSON.stringify(fenced),JSON.stringify(source!.rows),before.pluginId,before.pluginId,before.principalId,source!.rows.length]);
    current();
    if (result.changes !== records.length) deny();
  }
  return { snapshotId: source!.facts.snapshotId, sha256: source!.facts.sha256,
    heldCount: source!.rows.length, unknownPreserved: true, retryAllowed: false };
}
