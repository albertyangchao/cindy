import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
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
