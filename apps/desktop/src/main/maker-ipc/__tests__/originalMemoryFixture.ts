/** Synthetic small original-source inventory; never uses real user files. */
import Database from 'better-sqlite3';
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { approveMemorySources, originalDatabasePath } from '../restrictedPartnerLegacyMemory.js';
import type {
  OriginalMemoryInventory,
  PartnerRequirements,
} from '../restrictedPartnerRequirements.js';
export const memoryHash = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
export function originalMemoryFixture(present = false) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'original-memory-'))),
    durableRoot = path.join(root, 'durable');
  mkdirSync(durableRoot);
  writeFileSync(path.join(durableRoot, 'INTERESTS.md'), 'SYNTHETIC INTEREST rockets');
  writeFileSync(path.join(durableRoot, 'WORKLOG.md'), 'OLD INTENT MUST NOT LOAD');
  const database = originalDatabasePath(root);
  if (present) {
    mkdirSync(path.dirname(database), { recursive: true });
    const db = new Database(database);
    db.exec(
      "CREATE TABLE sticky_notes(namespace TEXT,note_key TEXT,content TEXT,updated_at INTEGER);INSERT INTO sticky_notes VALUES('mine','fact','SYNTHETIC preserved rockets',1),('default','unmapped','UNATTRIBUTED_EXCLUDED',1)",
    );
    db.close();
  }
  const inventory: OriginalMemoryInventory = {
    version: 1,
    evidenceRevision: 1,
    evidenceHash: 'b'.repeat(64),
    identityHash: 'a'.repeat(64),
    rootHash: memoryHash(root),
    durableRootHash: memoryHash(durableRoot),
    files: [
      { name: 'PROFILE.md', exists: false, sha256: null },
      { name: 'MEMORY.md', exists: false, sha256: null },
      {
        name: 'INTERESTS.md',
        exists: true,
        sha256: memoryHash(readFileSync(path.join(durableRoot, 'INTERESTS.md'))),
      },
    ],
    database: {
      state: present ? 'present' : 'absent',
      sha256: present ? memoryHash(readFileSync(database)) : null,
    },
  };
  return {
    root,
    durableRoot,
    database,
    inventory,
    approve: (reviewed = true) =>
      approveMemorySources(root, durableRoot, inventory, reviewed, () => {}),
    requirements: (principalId: string): PartnerRequirements => ({
      version: 1,
      revision: 2,
      principalId,
      addressHashes: ['a'.repeat(64)],
      source: {
        registry: 'c'.repeat(64),
        nativeConfig: 'd'.repeat(64),
        overlays: ['e'.repeat(64)],
      },
      tools: ['memory-read', 'memory-write', 'durable-memory-read'],
      purposes: ['memory', 'durable-files'],
      media: ['vision'],
      sourceInventory: inventory,
      excludedNamespaces: ['default'],
    }),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}
