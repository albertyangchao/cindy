import Database from 'better-sqlite3';
import { readFile, readdir } from 'node:fs/promises';
import { searchLegacyMemory, legacyMemoryNamespaces } from '../restrictedPartnerLegacyMemory.js';
import { mkdtemp, writeFile, mkdir, symlink, rm, realpath } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { expect, it } from 'vitest';
import { restrictedPartnerResources } from '../restrictedPartnerResources.js';
import type { RestrictedPartnerGrant } from '../restrictedPartnerExecution.js';
it('real approved-resource helper reads only selected facts and denies traversal, symlink and revocation', async () => {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'restricted-partner-resource-')));
  let valid = true;
  try {
    await mkdir(path.join(root, 'approved'));
    await writeFile(path.join(root, 'approved', 'facts.md'), 'APPROVED_PERSISTENT_FACT');
    await writeFile(path.join(root, 'private.md'), 'PRIVATE_OWNER_CONTEXT');
    await symlink(path.join(root, 'private.md'), path.join(root, 'approved', 'escape.md'));
    const g = {
      resources: [{ id: 'resource-1', path: path.join(root, 'approved') }],
    } as RestrictedPartnerGrant;
    const p = restrictedPartnerResources(g, () => {
      if (!valid) throw Error('REVOKED');
    });
    const read = p.tools.find((x) => x.name === 'partner_resource_read')!;
    const good = await read.invoke(
      { resourceId: 'resource-1', relativePath: 'facts.md' },
      { callId: 'call', runId: 'run' },
    );
    expect(good.success).toBe(true);
    expect(JSON.stringify(good)).toContain('APPROVED_PERSISTENT_FACT');
    for (const relativePath of ['../private.md', 'escape.md']) {
      const denied = await read.invoke(
        { resourceId: 'resource-1', relativePath },
        { callId: 'call', runId: 'run' },
      );
      expect(denied.success).toBe(false);
      expect(JSON.stringify(denied)).not.toContain('PRIVATE_OWNER_CONTEXT');
    }
    await expect(
      read.invoke(
        { resourceId: 'other', relativePath: 'facts.md' },
        { callId: 'call', runId: 'run' },
      ),
    ).rejects.toThrow('DENIED');
    valid = false;
    await expect(
      read.invoke(
        { resourceId: 'resource-1', relativePath: 'facts.md' },
        { callId: 'call', runId: 'run' },
      ),
    ).rejects.toThrow('REVOKED');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it('bounded resource/notes/legacy-memory search preserves purpose and current scope, never follows private links', async () => {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'restricted-search-')));
  let active = true;
  try {
    await mkdir(path.join(root, 'workspace'));
    await mkdir(path.join(root, 'notes'));
    await mkdir(path.join(root, 'memory'));
    for (const kind of ['workspace', 'notes', 'memory'])
      await writeFile(path.join(root, kind, 'facts.md'), kind + ' NEEDLE');
    await writeFile(path.join(root, 'secret.md'), 'PRIVATE NEEDLE');
    await symlink(path.join(root, 'secret.md'), path.join(root, 'notes', 'escape.md'));
    const grant = {
      resources: ['workspace', 'notes', 'memory'].map((k) => ({ id: k, path: path.join(root, k) })),
      resourceCoverage: { workspace: ['workspace'], notes: ['notes'], memory: ['memory'] },
    } as RestrictedPartnerGrant;
    const tools = restrictedPartnerResources(grant, () => {
      if (!active) throw Error('REVOKED');
    }).tools;
    for (const [name, id] of [['partner_notes_search', 'notes']] as const) {
      const result = await tools
        .find((t) => t.name === name)!
        .invoke({ query: 'NEEDLE' }, { callId: name, runId: 'run' });
      const text = JSON.stringify(result);
      expect(text).toContain(id + ' NEEDLE');
      expect(text).not.toContain('PRIVATE');
      expect(text).not.toContain('workspace NEEDLE');
      await expect(
        tools
          .find((t) => t.name === name)!
          .invoke({ query: 'NEEDLE', resourceId: 'workspace' }, { callId: 'cross', runId: 'run' }),
      ).rejects.toThrow('DENIED');
    }
    const search = tools.find((t) => t.name === 'partner_resource_search')!;
    await expect(
      search.invoke({ query: '', resourceId: 'notes' }, { callId: 'empty', runId: 'run' }),
    ).rejects.toThrow('DENIED');
    active = false;
    await expect(
      search.invoke({ query: 'NEEDLE' }, { callId: 'revoked', runId: 'run' }),
    ).rejects.toThrow('REVOKED');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it('actual bounded legacy SQLite namespace preserves original bytes, excludes other subject/summary, rejects model namespace override and active journals', async () => {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'legacy-memory-'))),
    file = path.join(root, 'memory.db');
  const db = new Database(file);
  db.exec(
    'CREATE TABLE sticky_notes(namespace TEXT,note_key TEXT,content TEXT,updated_at INTEGER);CREATE TABLE session_summaries(namespace TEXT,summary TEXT,updated_at INTEGER);',
  );
  db.prepare('INSERT INTO sticky_notes VALUES(?,?,?,1)').run(
    'subject-a',
    'fact',
    'NEEDLE durable fact',
  );
  db.prepare('INSERT INTO sticky_notes VALUES(?,?,?,1)').run(
    'subject-b',
    'private',
    'NEEDLE PRIVATE',
  );
  db.prepare('INSERT INTO session_summaries VALUES(?,?,1)').run(
    'subject-a',
    'NEEDLE old request DO NOT EXECUTE',
  );
  db.close();
  const original = await readFile(file),
    names = await readdir(root);
  let active = true;
  const current = () => {
    if (!active) throw Error('REVOKED');
  };
  try {
    expect(legacyMemoryNamespaces(file, current)).toEqual(['subject-a', 'subject-b']);
    const g = {
      resources: [{ id: 'memory', path: file }],
      resourceCoverage: { memory: ['memory'] },
      legacyMemory: { resourceId: 'memory', namespace: 'subject-a' },
    } as RestrictedPartnerGrant;
    const tool = restrictedPartnerResources(g, current).tools.find(
      (t) => t.name === 'partner_memory_search',
    )!;
    const result = await tool.invoke({ query: 'NEEDLE' }, { callId: 'read', runId: 'run' });
    expect(JSON.stringify(result)).toContain('durable fact');
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
    expect(JSON.stringify(result)).not.toContain('DO NOT EXECUTE');
    await expect(
      tool.invoke(
        { query: 'NEEDLE', namespace: 'subject-b' },
        { callId: 'override', runId: 'run' },
      ),
    ).rejects.toThrow('DENIED');
    expect(await readFile(file)).toEqual(original);
    expect(await readdir(root)).toEqual(names);
    await writeFile(file + '-wal', 'synthetic-active');
    expect(() => searchLegacyMemory(file, 'subject-a', 'NEEDLE', current)).toThrow('DENIED');
    await rm(file + '-wal');
    expect(() => searchLegacyMemory(file, null, 'NEEDLE', current)).toThrow('DENIED');
    active = false;
    expect(() => searchLegacyMemory(file, 'subject-a', 'NEEDLE', current)).toThrow('REVOKED');
    expect(await readFile(file)).toEqual(original);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
