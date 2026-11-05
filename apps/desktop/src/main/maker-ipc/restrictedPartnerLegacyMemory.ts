import Database from 'better-sqlite3';
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
export function legacyMemoryNamespaces(file: string, current: () => void): string[] {
  return opened(file, current, (db) => {
    const rows = db
      .prepare('SELECT DISTINCT substr(namespace,1,129) AS namespace FROM sticky_notes LIMIT 65')
      .all() as Array<{ namespace: unknown }>;
    if (rows.length > 64) deny();
    return rows.map((r) => {
      if (
        typeof r.namespace !== 'string' ||
        !r.namespace.length ||
        r.namespace.length > 128 ||
        /[\x00-\x1f]/.test(r.namespace)
      )
        deny();
      return r.namespace as string;
    });
  });
}
export function searchLegacyMemory(
  file: string,
  namespace: string | null,
  query: string,
  current: () => void,
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
      if (db.prepare('SELECT 1 FROM sticky_notes LIMIT 1').get()) deny();
      return { matches: [], partial: false, summaryExcluded: true };
    }
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
