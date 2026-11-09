import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { and, asc, eq, inArray, or, sql } from 'drizzle-orm';
import type { DbClient } from '../localDb/client/DbClient.js';
import { pluginTaskRequests } from '../localDb/schema.js';
import type { RestrictedPartnerGrant } from './restrictedPartnerExecution.js';
import type { OriginalMemoryInventory } from './restrictedPartnerRequirements.js';
import { validateOriginalInventory } from './restrictedPartnerRequirements.js';
import path from 'node:path';
import {
  lstatSync,
  realpathSync,
  existsSync,
  openSync,
  closeSync,
  readSync,
  fstatSync,
  constants,
} from 'node:fs';
const deny = (): never => {
  throw Error('RESTRICTED_PARTNER_MEMORY_SOURCE_DENIED');
};
/** Read a bounded consistent source into a private immutable SQLite buffer: never opens the source as SQLite or creates WAL/SHM/journal. */
function opened<T>(file: string, current: () => void, fn: (db: Database.Database) => T): T {
  let db: Database.Database | undefined;
  let fd: number | undefined;
  let primary = false;
  try {
    current();
    const before = lstatSync(file);
    const journals = () => ['-wal', '-shm', '-journal'].some((s) => existsSync(file + s));
    if (
      path.basename(file) !== 'memory.db' ||
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.size > 32 * 1024 * 1024 ||
      before.nlink !== 1 ||
      realpathSync(file) !== file ||
      journals() ||
      (typeof process.getuid === 'function' && before.uid !== process.getuid())
    )
      deny();
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (opened.ino !== before.ino || opened.dev !== before.dev || opened.size !== before.size)
      deny();
    const data = Buffer.alloc(before.size + 1);
    let size = 0;
    while (size < data.length) {
      current();
      const n = readSync(fd, data, size, data.length - size, null);
      if (!n) break;
      size += n;
    }
    const after = fstatSync(fd);
    closeSync(fd);
    fd = undefined;
    current();
    if (
      size !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ctimeMs !== before.ctimeMs ||
      after.size !== before.size ||
      journals() ||
      realpathSync(file) !== file ||
      lstatSync(file).ino !== before.ino
    )
      deny();
    db = new Database(data.subarray(0, size), { readonly: true });
    db.pragma('trusted_schema = OFF');
    db.pragma('query_only = ON');
    db.pragma('temp_store = MEMORY');
    const shape = db.prepare("SELECT type FROM sqlite_master WHERE name='sticky_notes'").get() as
      { type: string } | undefined;
    if (shape?.type !== 'table') deny();
    const cols = db.pragma('table_info(sticky_notes)') as Array<{ name: string }>;
    if (
      ['namespace', 'note_key', 'content', 'updated_at'].some(
        (k) => !cols.some((c) => c.name === k),
      )
    )
      deny();
    const result = fn(db);
    current();
    return result;
  } catch {
    primary = true;
    current();
    return deny();
  } finally {
    try {
      if (fd !== undefined) closeSync(fd);
      db?.close();
    } catch {
      if (!primary) deny();
    }
  }
}
export function legacyMemoryNamespaces(
  file: string,
  current: () => void,
  excluded: string[] = [],
): string[] {
  return opened(file, current, (db) => {
    const rows = db
      .prepare('SELECT DISTINCT substr(namespace,1,129) AS namespace FROM sticky_notes LIMIT 65')
      .all() as Array<{ namespace: unknown }>;
    if (rows.length > 64) deny();
    return rows
      .map((r) => {
        if (
          typeof r.namespace !== 'string' ||
          !r.namespace.length ||
          r.namespace.length > 128 ||
          /[\x00-\x1f]/.test(r.namespace)
        )
          deny();
        return r.namespace as string;
      })
      .filter((n) => !excluded.includes(n));
  });
}
export function searchLegacyMemory(
  file: string,
  namespace: string | null,
  query: string,
  current: () => void,
  excluded: string[] = [],
) {
  if (
    (namespace !== null &&
      (typeof namespace !== 'string' || !namespace.length || namespace.length > 128)) ||
    typeof query !== 'string' ||
    !query.length ||
    query.length > 256
  )
    deny();
  return opened(file, current, (db) => {
    if (namespace === null) {
      if (legacyMemoryNamespaces(file, current, excluded).length) deny();
      return { matches: [], partial: false, summaryExcluded: true };
    }
    if (excluded.includes(namespace)) deny();
    // Bound allocations before returning a value. Namespace never comes from model/plugin arguments.
    const rows = db
      .prepare(
        'SELECT substr(note_key,1,500) AS label, substr(content,1,800) AS content FROM sticky_notes WHERE namespace=? AND (instr(lower(substr(note_key,1,4096)),lower(?))>0 OR instr(lower(substr(content,1,65536)),lower(?))>0) ORDER BY updated_at DESC LIMIT 33',
      )
      .all(namespace, query, query) as Array<{ label: string; content: string }>;
    return {
      matches: rows
        .slice(0, 32)
        .map((r) => ({ source: 'legacy-sticky-note', label: r.label, content: r.content })),
      partial: rows.length > 32,
      summaryExcluded: true,
    };
  });
}

/** Private native owner approval. No paths/absence booleans are accepted on the plugin wire. */
export interface ApprovedMemorySources {
  root: string;
  durableRoot: string;
  inventory: OriginalMemoryInventory;
  snapshot: string;
}
const sourceHash = (v: string | Buffer) => createHash('sha256').update(v).digest('hex');
function sourceStat(file: string, directory: boolean) {
  const s = lstatSync(file);
  if (
    s.isSymbolicLink() ||
    realpathSync(file) !== file ||
    (directory ? !s.isDirectory() : !s.isFile()) ||
    (typeof process.getuid === 'function' && s.uid !== process.getuid()) ||
    (directory ? (s.mode & 0o500) !== 0o500 : (s.mode & 0o444) === 0) ||
    (!directory && s.nlink !== 1)
  )
    deny();
  return [s.dev, s.ino, s.size, s.mtimeMs, s.ctimeMs, s.mode, s.uid];
}
function optionalFile(file: string, limit: number): number[] | null {
  try {
    const s = sourceStat(file, false);
    if (s[2] > limit) deny();
    return s;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
}
export const originalDatabasePath = (root: string) =>
  path.join(root, '.bridge', 'runtime', 'memory.db');
function sourceBytes(file: string, limit: number, current: () => void): Buffer {
  current();
  const before = sourceStat(file, false);
  if (before[2] > limit) deny();
  let fd: number | undefined;
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (stat.ino !== before[1] || stat.dev !== before[0]) deny();
    const bytes = Buffer.alloc(Number(before[2]) + 1);
    let n = 0;
    while (n < bytes.length) {
      current();
      const count = readSync(fd, bytes, n, bytes.length - n, null);
      if (!count) break;
      n += count;
    }
    if (n !== before[2] || JSON.stringify(sourceStat(file, false)) !== JSON.stringify(before))
      deny();
    current();
    return bytes.subarray(0, n);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
function sourceSnapshot(
  source: Pick<ApprovedMemorySources, 'root' | 'durableRoot' | 'inventory'>,
  current: () => void,
  verifyBytes: boolean,
) {
  current();
  const { root, durableRoot, inventory: i } = source;
  validateOriginalInventory(i);
  if (
    !path.isAbsolute(root) ||
    !path.isAbsolute(durableRoot) ||
    sourceHash(root) !== i.rootHash ||
    sourceHash(durableRoot) !== i.durableRootHash
  )
    deny();
  const records: unknown[] = [sourceStat(root, true), sourceStat(durableRoot, true)];
  for (const f of i.files) {
    const name = path.join(durableRoot, f.name),
      s = optionalFile(name, 65536);
    if (Boolean(s) !== f.exists) deny();
    records.push([f.name, s]);
    if (s && verifyBytes && sourceHash(sourceBytes(name, 65536, current)) !== f.sha256) deny();
    current();
  }
  let missing = false;
  for (const piece of ['.bridge', '.bridge/runtime']) {
    const target = path.join(root, piece);
    try {
      if (missing) {
        try {
          lstatSync(target);
          deny();
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
        }
      } else records.push([piece, sourceStat(target, true)]);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
      missing = true;
      records.push([piece, null]);
    }
  }
  const db = originalDatabasePath(root),
    stat = missing ? null : optionalFile(db, 32 * 1024 * 1024);
  if ((i.database.state === 'present') !== Boolean(stat)) deny();
  records.push(['memory.db', stat]);
  if (stat) {
    for (const suffix of ['-wal', '-shm', '-journal']) {
      try {
        lstatSync(db + suffix);
        deny();
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
      }
    }
    if (verifyBytes && sourceHash(sourceBytes(db, 32 * 1024 * 1024, current)) !== i.database.sha256)
      deny();
  }
  current();
  return sourceHash(JSON.stringify(records));
}
function approveMemorySourcesImpl(
  root: string,
  durableRoot: string,
  inventory: OriginalMemoryInventory,
  historicalAbsenceReviewed: boolean,
  current: () => void,
): ApprovedMemorySources {
  if (inventory.database.state === 'absent' && !historicalAbsenceReviewed) deny();
  const source = { root, durableRoot, inventory: structuredClone(inventory) };
  const snapshot = sourceSnapshot(source, current, true);
  current();
  if (sourceSnapshot(source, current, false) !== snapshot) deny();
  return { ...source, snapshot };
}
function assertMemorySourcesImpl(source: ApprovedMemorySources, current: () => void) {
  if (
    !source ||
    Object.keys(source).sort().join(',') !== 'durableRoot,inventory,root,snapshot' ||
    !/^[a-f0-9]{64}$/.test(source.snapshot) ||
    sourceSnapshot(source, current, false) !== source.snapshot
  )
    deny();
}
function readOriginalDurableFilesImpl(source: ApprovedMemorySources, current: () => void) {
  assertMemorySources(source, current);
  const files = source.inventory.files.map((f) => ({
    name: f.name,
    exists: f.exists,
    text: f.exists
      ? Array.from(
          sourceBytes(path.join(source.durableRoot, f.name), 65536, current).toString('utf8'),
        )
          .slice(0, 12000)
          .join('')
      : null,
    partial: f.exists ? sourceStat(path.join(source.durableRoot, f.name), false)[2] > 12000 : false,
  }));
  assertMemorySources(source, current);
  return {
    files,
    source: 'original-subject-long-term-data',
    worklogExcluded: true,
    summaryExcluded: true,
    notExecutableIntent: true,
  };
}

// Public errors are finite; never return fs paths or arbitrary exception messages.
export function approveMemorySources(...args: Parameters<typeof approveMemorySourcesImpl>) {
  try {
    return approveMemorySourcesImpl(...args);
  } catch {
    return deny();
  }
}
export function assertMemorySources(...args: Parameters<typeof assertMemorySourcesImpl>) {
  try {
    return assertMemorySourcesImpl(...args);
  } catch {
    return deny();
  }
}
export function readOriginalDurableFiles(...args: Parameters<typeof readOriginalDurableFilesImpl>) {
  try {
    return readOriginalDurableFilesImpl(...args);
  } catch {
    return deny();
  }
}

type MigrationSource = { sourceKey: string; domainId: string; principalId: string };
export type RestrictedPartnerMigrationRecord = MigrationSource & (
  | { kind: 'history'; chatId: string; state: 'COMPLETE' | 'UNKNOWN' | 'EXECUTION_UNKNOWN' | 'SEND_UNKNOWN' | 'PREPARED'; question?: string; answer?: string }
  | { kind: 'facts'; facts: string[] }
  | { kind: 'document'; resourceId: string; nativeResourceId: string; text: string }
);
export interface RestrictedPartnerMigrationSnapshot {
  version: 1;
  domainId: string;
  principalId: string;
  sourceId: string;
  records: RestrictedPartnerMigrationRecord[];
}
const migrationDenied: (code?: string) => never = (code = 'RESTRICTED_PARTNER_MIGRATION_DENIED'): never => {
  throw Error(code);
};
const canonicalMigration = (value: unknown): string => {
  if (Array.isArray(value)) return '[' + value.map(canonicalMigration).join(',') + ']';
  if (value && typeof value === 'object')
    return '{' + Object.keys(value).sort().map((key) =>
      JSON.stringify(key) + ':' + canonicalMigration((value as Record<string, unknown>)[key]),
    ).join(',') + '}';
  const encoded = JSON.stringify(value);
  if (encoded === undefined) return migrationDenied();
  return encoded;
};
const migrationHash = (value: unknown) => createHash('sha256').update(canonicalMigration(value)).digest('hex');
const migrationObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)));
const migrationKeys = (value: Record<string, unknown>, keys: string[], optional: string[] = []) =>
  keys.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
  Object.keys(value).every((key) => keys.includes(key) || optional.includes(key));
const migrationId = (value: unknown) => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(value);
const migrationKey = (value: unknown) => typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,200}$/.test(value);
const migrationText = (value: unknown, max: number, empty = false) =>
  typeof value === 'string' && (empty || value.length > 0) && value.length <= max && !value.includes('\0');
function documentGrant(g: RestrictedPartnerGrant, resourceId: string) {
  return g.resourceIds.includes(resourceId) && g.resources.some((resource) => resource.id === resourceId);
}
/** The source identity is never inferred from a label, partner name, address count or is_parent. */
function migrationSnapshot(value: unknown, g: RestrictedPartnerGrant): RestrictedPartnerMigrationSnapshot {
  if (!migrationObject(value) || !migrationKeys(value, ['version', 'domainId', 'principalId', 'sourceId', 'records']) ||
      value.version !== 1 || !migrationId(value.domainId) || !migrationId(value.principalId) ||
      !migrationKey(value.sourceId) || migrationHash([value.domainId, value.principalId]) !== g.principalId ||
      !Array.isArray(value.records) || value.records.length > 128 ||
      Buffer.byteLength(JSON.stringify(value)) > 512 * 1024)
    migrationDenied();
  const seen = new Set<string>();
  for (const raw of value.records as unknown[]) {
    if (!migrationObject(raw) || !migrationKey(raw.sourceKey) || seen.has(raw.sourceKey as string) ||
        raw.domainId !== value.domainId || raw.principalId !== value.principalId)
      migrationDenied();
    seen.add(raw.sourceKey as string);
    const common = ['sourceKey', 'domainId', 'principalId', 'kind'];
    if (raw.kind === 'history') {
      if (!migrationKeys(raw, [...common, 'chatId', 'state'], ['question', 'answer']) ||
          !migrationText(raw.chatId, 256) ||
          typeof raw.state !== 'string' || !['COMPLETE', 'UNKNOWN', 'EXECUTION_UNKNOWN', 'SEND_UNKNOWN', 'PREPARED'].includes(raw.state) ||
          (raw.state === 'COMPLETE' && (!migrationText(raw.question, 120000) || !migrationText(raw.answer, 120000) ||
            !(raw.question as string).trim() || !(raw.answer as string).trim())) ||
          (raw.question !== undefined && !migrationText(raw.question, 120000, true)) ||
          (raw.answer !== undefined && !migrationText(raw.answer, 120000, true)))
        migrationDenied();
    } else if (raw.kind === 'facts') {
      if (!migrationKeys(raw, [...common, 'facts']) || !Array.isArray(raw.facts) || raw.facts.length > 32 ||
          raw.facts.some((fact) => !migrationText(fact, 500, true))) migrationDenied();
    } else if (raw.kind === 'document') {
      if (!migrationKeys(raw, [...common, 'resourceId', 'nativeResourceId', 'text']) ||
          !migrationId(raw.resourceId) || !migrationKey(raw.nativeResourceId) ||
          !migrationText(raw.text, 8000) || !(raw.text as string).trim() || !documentGrant(g, raw.nativeResourceId as string))
        migrationDenied();
    } else migrationDenied();
  }
  return {
    version: 1,
    domainId: value.domainId as string,
    principalId: value.principalId as string,
    sourceId: value.sourceId as string,
    records: structuredClone(value.records as RestrictedPartnerMigrationRecord[])
      .sort((a, b) => a.sourceKey < b.sourceKey ? -1 : a.sourceKey > b.sourceKey ? 1 : 0),
  };
}
const migrationPrefix = (g: RestrictedPartnerGrant) =>
  'restricted:migration:' + migrationHash([g.pluginId, g.principalId, g.partnerId]) + ':';
function migrationRow(g: RestrictedPartnerGrant, sourceId: string, record: RestrictedPartnerMigrationRecord) {
  const key = migrationHash([sourceId, record.sourceKey]);
  const targetId = migrationPrefix(g) + key;
  return {
    id: 'restricted-migration:' + migrationHash([g.pluginId, g.principalId, g.partnerId, sourceId, record.sourceKey]),
    pluginId: g.pluginId,
    operation: 'target',
    targetId,
    requestKey: key,
    fingerprint: migrationHash(record),
    payload: canonicalMigration({ version: 1, pluginId: g.pluginId, principalId: g.principalId,
      partnerId: g.partnerId, sourceId, record }),
    revision: 1,
  };
}
type MigrationRow = ReturnType<typeof migrationRow>;
function sameMigrationRow(row: MigrationRow, expected: MigrationRow) {
  return Object.entries(expected).every(([key, value]) => row[key as keyof MigrationRow] === value);
}
async function savedMigrationGrant(db: DbClient, g: RestrictedPartnerGrant, current: () => void) {
  current();
  const [row] = await db.drizzle.select().from(pluginTaskRequests).where(and(
    eq(pluginTaskRequests.pluginId, g.pluginId), eq(pluginTaskRequests.operation, 'target'),
    eq(pluginTaskRequests.targetId, 'restricted:grant:' + g.id),
  )).limit(1);
  current();
  if (!row || row.revision !== g.revision || row.payload !== JSON.stringify(g)) migrationDenied();
}
/** Explicit local migration only. A single conditional INSERT makes each batch atomic, never sends or starts a model. */
export async function migrateRestrictedPartnerData(
  db: DbClient,
  g: RestrictedPartnerGrant,
  mode: 'dry-run' | 'apply',
  value: unknown,
  current: () => void,
) {
  current();
  if (!g.enabled || !['dry-run', 'apply'].includes(mode) || (mode === 'apply' && g.dispatchEnabled))
    migrationDenied();
  const snapshot = migrationSnapshot(value, g);
  await savedMigrationGrant(db, g, current);
  const rows = snapshot.records.filter((record) => record.kind !== 'history' || record.state === 'COMPLETE')
    .map((record) => migrationRow(g, snapshot.sourceId, record));
  const existing = rows.length ? await db.drizzle.select().from(pluginTaskRequests)
    .where(or(inArray(pluginTaskRequests.id, rows.map((row) => row.id)), and(
      eq(pluginTaskRequests.pluginId, g.pluginId), eq(pluginTaskRequests.operation, 'target'),
      inArray(pluginTaskRequests.targetId, rows.map((row) => row.targetId)),
    ))) : [];
  current();
  const before = new Map(existing.map((row) => [row.id, row]));
  for (const row of rows) {
    const old = before.get(row.id);
    if (old && !sameMigrationRow(old, row)) migrationDenied('RESTRICTED_PARTNER_MIGRATION_CONFLICT');
    if (existing.some((saved) => saved.targetId === row.targetId && !sameMigrationRow(saved, row)))
      migrationDenied('RESTRICTED_PARTNER_MIGRATION_CONFLICT');
  }
  let imported = 0;
  const inserted = new Set<string>();
  if (mode === 'apply' && rows.some((row) => !before.has(row.id))) {
    current();
    const input = JSON.stringify(rows);
    // The old grant and every colliding source key are checked in the same SQLite statement as all inserts.
    const result = await db.query<{ id: string }>(`
      INSERT INTO plugin_task_requests
        (id,plugin_id,operation,target_id,request_key,fingerprint,payload,revision,created_at)
      SELECT json_extract(i.value,'$.id'),json_extract(i.value,'$.pluginId'),'target',
        json_extract(i.value,'$.targetId'),json_extract(i.value,'$.requestKey'),
        json_extract(i.value,'$.fingerprint'),json_extract(i.value,'$.payload'),1,?
      FROM json_each(?) AS i
      WHERE EXISTS (SELECT 1 FROM plugin_task_requests AS g
        WHERE g.plugin_id=? AND g.operation='target' AND g.target_id=? AND g.revision=? AND g.payload=?)
      AND NOT EXISTS (SELECT 1 FROM plugin_task_requests AS old JOIN json_each(?) AS candidate
        ON old.id=json_extract(candidate.value,'$.id') OR
          (old.plugin_id=json_extract(candidate.value,'$.pluginId') AND old.operation='target'
            AND old.target_id=json_extract(candidate.value,'$.targetId'))
        WHERE old.id IS NOT json_extract(candidate.value,'$.id')
          OR old.plugin_id IS NOT json_extract(candidate.value,'$.pluginId') OR old.operation IS NOT 'target'
          OR old.target_id IS NOT json_extract(candidate.value,'$.targetId')
          OR old.request_key IS NOT json_extract(candidate.value,'$.requestKey')
          OR old.fingerprint IS NOT json_extract(candidate.value,'$.fingerprint')
          OR old.payload IS NOT json_extract(candidate.value,'$.payload') OR old.revision IS NOT 1)
      ON CONFLICT DO NOTHING RETURNING id`,
    [Date.now(), input, g.pluginId, 'restricted:grant:' + g.id, g.revision, JSON.stringify(g), input]);
    current();
    for (const row of result) inserted.add(row.id);
    imported = inserted.size;
    const after = await db.drizzle.select().from(pluginTaskRequests)
      .where(inArray(pluginTaskRequests.id, rows.map((row) => row.id)));
    current();
    const saved = new Map(after.map((row) => [row.id, row]));
    if (rows.some((row) => !saved.has(row.id) || !sameMigrationRow(saved.get(row.id)!, row)))
      migrationDenied('RESTRICTED_PARTNER_MIGRATION_CONFLICT');
  }
  await savedMigrationGrant(db, g, current);
  const records = snapshot.records.map((record) => ({
    sourceKey: record.sourceKey,
    kind: record.kind,
    digest: migrationHash(record),
    status: record.kind === 'history' && record.state !== 'COMPLETE' ? 'EXCLUDED_UNKNOWN' as const
      : (mode === 'apply' ? !inserted.has(migrationRow(g, snapshot.sourceId, record).id)
        : before.has(migrationRow(g, snapshot.sourceId, record).id)) ? 'DUPLICATE' as const : 'IMPORT' as const,
  }));
  return { version: 1, principalId: g.principalId, partnerId: g.partnerId, grantId: g.id,
    grantRevision: g.revision, mode, snapshotDigest: migrationHash(snapshot), records,
    planned: records.filter((record) => record.status === 'IMPORT').length,
    imported, duplicates: records.filter((record) => record.status === 'DUPLICATE').length,
    excluded: records.filter((record) => record.status === 'EXCLUDED_UNKNOWN').length, effects: 0 };
}

/** Bounded read of imported data; it cannot create claims, task intents, owner resources or new memory. */
export async function readRestrictedPartnerMigration(
  db: DbClient,
  g: RestrictedPartnerGrant,
  scope: { chatId: string; memoryRead: boolean },
  options: { kind: 'history' | 'facts' | 'document'; query?: string; sourceId?: string; sourceKey?: string;
    offset?: number; textOffset?: number; factOffset?: number; limit?: number },
  current: () => void,
) {
  current();
  const offset = options.offset ?? 0, limit = options.limit ?? 8;
  const textOffset = options.textOffset ?? 0, factOffset = options.factOffset ?? 0;
  if (!['history', 'facts', 'document'].includes(options.kind) ||
      (options.kind === 'facts' && !scope.memoryRead) || !migrationText(scope.chatId, 256) ||
      !Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 16 ||
      (options.query !== undefined && !migrationText(options.query, 200)) ||
      (options.sourceId !== undefined && !migrationKey(options.sourceId)) ||
      (options.sourceKey !== undefined && !migrationKey(options.sourceKey)) ||
      !Number.isSafeInteger(textOffset) || textOffset < 0 || textOffset > 120000 ||
      !Number.isSafeInteger(factOffset) || factOffset < 0 || factOffset > 32 ||
      (options.kind === 'facts' && options.textOffset !== undefined) ||
      (options.kind !== 'facts' && options.factOffset !== undefined) ||
      ((textOffset > 0 || factOffset > 0) && (!options.sourceId || !options.sourceKey))) migrationDenied();
  const t = pluginTaskRequests;
  const prefix = migrationPrefix(g);
  const permittedResources = g.resourceIds.filter((id) => documentGrant(g, id));
  if (options.kind === 'document' && !permittedResources.length)
    return { version: 1, kind: options.kind, records: [], partial: false, nextOffset: null };
  const field = (key: string) => sql`(CASE WHEN json_valid(${t.payload}) THEN json_extract(${t.payload}, ${key}) ELSE NULL END)`;
  const rows = await db.drizzle.select().from(t).where(and(
    eq(t.pluginId, g.pluginId), eq(t.operation, 'target'),
    sql`substr(${t.targetId},1,${prefix.length})=${prefix}`,
    sql`${field('$.record.kind')}=${options.kind}`,
    ...(options.kind === 'history' ? [sql`${field('$.record.chatId')}=${scope.chatId}`, sql`${field('$.record.state')}='COMPLETE'`] : []),
    ...(options.kind === 'document' ? [inArray(field('$.record.nativeResourceId'), permittedResources)] : []),
    ...(options.sourceId ? [sql`${field('$.sourceId')}=${options.sourceId}`] : []),
    ...(options.sourceKey ? [sql`${field('$.record.sourceKey')}=${options.sourceKey}`] : []),
    ...(options.query ? [sql`instr(lower(COALESCE(${field('$.record.text')},'') || COALESCE(${field('$.record.question')},'') || COALESCE(${field('$.record.answer')},'') || COALESCE(${field('$.record.facts')},'')),lower(${options.query}))>0`] : []),
  )).orderBy(asc(t.targetId)).limit(limit + 1).offset(offset);
  current();
  type Continuation = { sourceId: string; sourceKey: string; textOffset?: number; factOffset?: number };
  const records: Array<RestrictedPartnerMigrationRecord & { sourceId: string;
    textOffset?: number; factOffset?: number; continuation: Continuation | null }> = [];
  for (const row of rows.slice(0, limit)) {
    let saved: { version: number; pluginId: string; principalId: string; partnerId: string; sourceId: string; record: RestrictedPartnerMigrationRecord };
    try { saved = JSON.parse(row.payload); } catch { migrationDenied(); }
    if (!migrationObject(saved!) || !migrationKeys(saved!, ['version', 'pluginId', 'principalId', 'partnerId', 'sourceId', 'record']) ||
        saved!.version !== 1 || saved!.pluginId !== g.pluginId || saved!.principalId !== g.principalId ||
        saved!.partnerId !== g.partnerId || !migrationObject(saved!.record))
      migrationDenied();
    const snapshot = migrationSnapshot({ version: 1, domainId: saved!.record.domainId,
      principalId: saved!.record.principalId, sourceId: saved!.sourceId, records: [saved!.record] }, g);
    if (!sameMigrationRow(row, migrationRow(g, snapshot.sourceId, snapshot.records[0]!))) migrationDenied();
    const original = snapshot.records[0]!;
    const provenance = { sourceId: snapshot.sourceId, sourceKey: original.sourceKey };
    let record: (typeof records)[number];
    if (original.kind === 'history') {
      const end = textOffset + 2000;
      const question = Array.from(original.question!), answer = Array.from(original.answer!);
      record = { ...original, sourceId: snapshot.sourceId, textOffset,
        question: question.slice(textOffset, end).join(''), answer: answer.slice(textOffset, end).join(''),
        continuation: Math.max(question.length, answer.length) > end
          ? { ...provenance, textOffset: end } : null };
    } else if (original.kind === 'document') {
      const end = textOffset + 4000;
      const content = Array.from(original.text);
      record = { ...original, sourceId: snapshot.sourceId, textOffset, text: content.slice(textOffset, end).join(''),
        continuation: content.length > end ? { ...provenance, textOffset: end } : null };
    } else {
      const end = factOffset + 8;
      record = { ...original, sourceId: snapshot.sourceId, factOffset, facts: original.facts.slice(factOffset, end),
        continuation: original.facts.length > end ? { ...provenance, factOffset: end } : null };
    }
    // Bound encoded output too: control characters can expand sixfold in JSON.
    // Full immutable source stays in SQLite; exact source continuations lose no text or facts.
    if (Buffer.byteLength(JSON.stringify([...records, record])) > 48000) break;
    records.push(record);
  }
  current();
  return { version: 1, kind: options.kind, records,
    ...(options.kind === 'history' ? { chronology: 'unspecified' } : {}),
    partial: rows.length > records.length || records.some((record) => record.continuation !== null),
    nextOffset: rows.length > records.length ? offset + records.length : null };
}
