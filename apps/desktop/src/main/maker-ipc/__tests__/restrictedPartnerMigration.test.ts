// Production boundaries: createRestrictedPartnerHost migration -> original receipt table,
// and restrictedConversation -> real bots.createChannelLane transaction + scoped tools.
// Covers W1 history/facts/documents continuity and isolation with real in-memory SQLite;
// the existing Integrated test covers media/native execution, not explicit migration.
// No native model, network, installed runtime, real owner directory or live migration.
import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { restrictedConversation } from '../restrictedPartnerConversation.js';
import { migrationFixture, migrationTool } from './restrictedPartnerMigrationFixture.js';

const sha = (value: string) => createHash('sha256').update(value).digest('hex');

it('Host dry-run produces a stable exact subject manifest without any durable write or UNKNOWN promotion', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const unresolved = { ...f.claim(), runId: 'unresolved-native', inputId: 'unresolved-native' };
  expect(await f.store.reserve(unresolved)).toBe(true);
  const before = f.rows();
  const report = await f.migrate('dry-run');
  expect(report).toMatchObject({ version: 1, principalId: f.principalId, partnerId: 'bot_real',
    grantId: f.grant.id, grantRevision: 1, mode: 'dry-run', planned: 3, imported: 0, duplicates: 0, excluded: 1, effects: 0 });
  expect(report.records.map((row: any) => [row.sourceKey, row.status])).toEqual([
    ['document:1', 'IMPORT'], ['facts:1', 'IMPORT'], ['turn:1', 'IMPORT'], ['turn:unknown', 'EXCLUDED_UNKNOWN'],
  ]);
  expect(report.snapshotDigest).toMatch(/^[a-f0-9]{64}$/);
  const reorder = await f.migrate('dry-run', { ...f.snapshot, records: [...f.snapshot.records].reverse() });
  expect(reorder).toEqual(report);
  expect(f.rows()).toEqual(before);
  expect((await f.store.readClaim('plugin', unresolved.inputId))?.state).toBe('UNKNOWN');
  expect(f.effectCalls).toBe(0);
});

it('apply is idempotent across retries, record reordering and batch boundaries; changed source keys reject atomically', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const first = await f.migrate('apply');
  expect(first).toMatchObject({ planned: 3, imported: 3, duplicates: 0, excluded: 1, effects: 0 });
  const saved = f.rows();
  const again = await f.migrate('apply', { ...f.snapshot, records: [...f.snapshot.records].reverse() });
  expect(again).toMatchObject({ planned: 0, imported: 0, duplicates: 3, excluded: 1 });
  expect(again.records.map((row: any) => row.digest)).toEqual(first.records.map((row: any) => row.digest));
  const part = { ...f.snapshot, records: [f.snapshot.records[0]!] };
  expect(await f.migrate('apply', part)).toMatchObject({ imported: 0, duplicates: 1 });
  expect(await f.migrate('dry-run')).toMatchObject({ planned: 0, imported: 0, duplicates: 3 });
  expect(f.rows()).toEqual(saved);
  const changed = { ...f.snapshot, records: [
    { ...f.snapshot.records[0]!, answer: 'Changed original data' },
    { ...f.scope, sourceKey: 'new-fact', kind: 'facts', facts: ['Must not partly commit'] },
  ] };
  await expect(f.migrate('apply', changed)).rejects.toThrow('MIGRATION_CONFLICT');
  expect(f.rows()).toEqual(saved);
  expect(f.imports()).toHaveLength(3);
  expect(f.effectCalls).toBe(0);
});

it('concurrent identical applies report only actual inserts, while divergent batches cannot partially write', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const reports = await Promise.all([f.migrate('apply'), f.migrate('apply')]);
  expect(reports.map((report) => report.imported).sort()).toEqual([0, 3]);
  expect(reports.map((report) => report.duplicates).sort()).toEqual([0, 3]);
  for (const report of reports) expect(report.planned).toBe(report.imported);
  expect(f.imports()).toHaveLength(3);
  const fresh = { ...f.snapshot, sourceId: 'racing_export', records: [
    { ...f.scope, sourceKey: 'common', kind: 'facts', facts: ['Original'] },
  ] };
  const changed = { ...fresh, records: [
    { ...fresh.records[0]!, facts: ['Divergent'] },
    { ...f.scope, sourceKey: 'other', kind: 'facts', facts: ['No partial write'] },
  ] };
  const results = await Promise.allSettled([f.migrate('apply', fresh), f.migrate('apply', changed)]);
  expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
  expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  const added = f.imports().filter((row: any) => JSON.parse(row.payload).sourceId === 'racing_export');
  const winner = results[0]!.status === 'fulfilled' ? 1 : 2;
  expect(added).toHaveLength(winner);
});

it('exact source schema and native owner grants deny mixed subjects, guessed partners and undeclared document resources', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const before = f.rows();
  const mutations: Array<(value: any) => void> = [
    (value) => { value.principalId = 'owner'; },
    (value) => { value.records[0].domainId = 'foreign_domain'; },
    (value) => { value.records[0].principalId = 'foreign_subject'; },
    (value) => { value.records[0].ownerPath = '/synthetic/owner'; },
    (value) => { value.records[0].state = ['COMPLETE']; },
    (value) => { value.records[0].state = 'DONE'; },
    (value) => { value.records[3].nativeResourceId = 'ungranted-native-resource'; },
    (value) => { value.records.push(structuredClone(value.records[0])); },
    (value) => { value.sourceId = '../foreign'; },
    (value) => { value.records[0].question = 'x'.repeat(120001); },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(f.snapshot); mutate(value);
    await expect(f.migrate('apply', value)).rejects.toThrow('MIGRATION_DENIED');
  }
  for (const extra of [{ partnerId: 'guessed' }, { expectedRevision: 0 }, { owner: true }])
    await expect(f.call({ operation: 'migration', principalId: f.principalId, partnerId: f.grant.partnerId,
      expectedRevision: f.grant.revision, mode: 'apply', snapshot: f.snapshot, ...extra })).rejects.toThrow();
  expect(f.rows()).toEqual(before);
  expect(f.effectCalls).toBe(0);
});

it('every noncomplete history state stays excluded and never creates native claims or completion receipts', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const before = f.rows();
  const value = { ...f.snapshot, records: ['UNKNOWN', 'EXECUTION_UNKNOWN', 'SEND_UNKNOWN', 'PREPARED'].map((state) => ({
    ...f.scope, sourceKey: 'old:' + state, kind: 'history', chatId: f.channel.chatId, state,
    question: 'Old intent', answer: 'Unverified candidate output',
  })) };
  expect(await f.migrate('apply', value)).toMatchObject({ planned: 0, imported: 0, duplicates: 0, excluded: 4, effects: 0 });
  expect(f.rows()).toEqual(before);
  expect(f.effectCalls).toBe(0);
});

it('apply requires a fenced current grant, and a persisted grant change at the write boundary prevents the whole batch', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  f.beforeWrite(async () => { expect(await f.store.control(f.grant, true)).toBeDefined(); });
  await expect(f.migrate('apply')).rejects.toThrow();
  expect(f.imports()).toHaveLength(0);
  await expect(f.migrate('apply')).rejects.toThrow('MIGRATION_DENIED');
  expect(await f.migrate('dry-run')).toMatchObject({ planned: 3, imported: 0 });
  expect(f.imports()).toHaveLength(0);
  expect(f.effectCalls).toBe(0);
});

it('a concurrent same-namespace row with a foreign request key blocks every migration insert', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  // The hook sits at the real SQLite boundary after Host preflight; it does not replace the INSERT.
  const prefix = 'restricted:migration:' + sha(JSON.stringify(['plugin', f.principalId, f.grant.partnerId])) + ':';
  const target = prefix + sha(JSON.stringify([f.snapshot.sourceId, 'turn:1']));
  f.beforeWrite(() => {
    f.sqlite.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)').run(
      'foreign-row', 'plugin', 'target', target, 'foreign-request-key', 'foreign-fingerprint', '{}', 1, Date.now());
  });
  await expect(f.migrate('apply')).rejects.toThrow('MIGRATION_CONFLICT');
  expect(f.imports()).toHaveLength(1);
  expect((f.imports()[0] as any).id).toBe('foreign-row');
  expect(f.effectCalls).toBe(0);
});

it('revocation during an awaited Host read prevents migration and invalidates existing native archive tools', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  await f.migrate('apply');
  const conversation = await f.conversation();
  const saved = f.rows();
  const pending = f.migrate('dry-run');
  queueMicrotask(f.revoke);
  await expect(pending).rejects.toThrow('REVOKED');
  await expect(migrationTool(conversation, 'partner_migrated_data', { kind: 'history' })).rejects.toThrow('REVOKED');
  expect(f.rows()).toEqual(saved);
  expect(f.effectCalls).toBe(0);
});

it('native context and scoped tools use imported history/facts/documents without owner or cross-chat inheritance', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  await f.migrate('apply');
  const conversation = await f.conversation();
  expect(conversation.context).toContain('Earlier answer');
  expect(conversation.context).toContain('unspecified chronology');
  expect(conversation.context).not.toContain('Never replay this');
  const history = (await migrationTool(conversation, 'partner_history', {})).value;
  expect(history).toContainEqual(expect.objectContaining({ source: 'imported-archive', sourceId: f.snapshot.sourceId,
    sourceKey: 'turn:1', chronology: 'unspecified', question: 'Earlier question', answer: 'Earlier answer' }));
  expect((await migrationTool(conversation, 'partner_migrated_data', { kind: 'facts' })).value.records[0].facts)
    .toEqual(['Approved subject fact']);
  expect((await migrationTool(conversation, 'partner_migrated_data', { kind: 'document' })).value.records[0].text)
    .toBe('Approved subject document');
  const generation = await f.conversation({ generation: 'generation_2' });
  expect(generation.laneSessionId).not.toBe(conversation.laneSessionId);
  expect(generation.context).toContain('Earlier answer');
  const otherChat = await f.conversation({ chatId: 'unrelated_chat' });
  expect(otherChat.context).not.toContain('Earlier answer');
  expect((await migrationTool(otherChat, 'partner_migrated_data', { kind: 'history' })).value.records).toEqual([]);
  // Same subject aliases may share durable facts; their chat transcripts remain separate.
  expect((await migrationTool(otherChat, 'partner_migrated_data', { kind: 'facts' })).value.records).toHaveLength(1);
  const memoryDenied = await f.conversation({ memoryRead: false });
  expect(memoryDenied.tools.some((tool) => tool.name === 'partner_memory')).toBe(false);
  await expect(migrationTool(memoryDenied, 'partner_migrated_data', { kind: 'facts' })).rejects.toThrow('MIGRATION_DENIED');

  const foreignScope = { ...f.scope, principalId: 'subject_B' };
  const foreignId = sha(JSON.stringify([foreignScope.domainId, foreignScope.principalId]));
  const foreignBinding = await f.call({ operation: 'bind', principalId: foreignId, partnerId: 'bot_real', expectedRevision: 0 });
  const foreignGrant = (await f.store.readGrant('plugin', foreignBinding.grantId))!;
  const foreignClaim = { ...f.claim(foreignScope), principalId: foreignId, grantId: foreignGrant.id };
  const foreign = await restrictedConversation(f.db, foreignGrant, foreignClaim, f.route, f.current);
  for (const kind of ['history', 'facts', 'document'])
    expect((await migrationTool(foreign, 'partner_migrated_data', { kind })).value.records).toEqual([]);
  await expect(f.conversation({ principalId: 'owner' })).rejects.toThrow('HISTORY_DENIED');

  await f.rebind([]);
  const withdrawn = await f.conversation();
  expect(withdrawn.context).toContain('Earlier answer');
  expect((await migrationTool(withdrawn, 'partner_migrated_data', { kind: 'document' })).value.records).toEqual([]);
  expect((await migrationTool(withdrawn, 'partner_migrated_data', { kind: 'facts' })).value.records).toHaveLength(1);
  await expect(f.migrate('apply')).rejects.toThrow('MIGRATION_DENIED');
  expect(f.effectCalls).toBe(0);
});

it('scope is applied in SQL before the history limit so unrelated receipts cannot crowd out a completed native turn', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const conversation = await f.conversation();
  const completed = { ...f.claim(), runId: 'completed-native', inputId: 'completed-native', inputText: 'Live native question' };
  expect(await f.store.reserve(completed)).toBe(true);
  expect(await f.store.recordExecution(completed.runId, 'native-thread', 'native-route')).toBe(true);
  expect(await f.store.recordResult(completed.runId, 'native-answer', 'Live native answer', undefined, conversation.laneSessionId)).toBe(true);
  expect(await f.store.complete(completed.runId)).toBe(true);
  const insert = f.sqlite.prepare('INSERT INTO plugin_task_requests VALUES(?,?,?,?,?,?,?,?,?)');
  f.sqlite.transaction(() => {
    for (let index = 0; index < 600; index++) {
      const key = 'noise:' + index;
      insert.run(key, 'plugin', 'target', 'restricted:input:' + key, key, 'synthetic', JSON.stringify({
        ...completed, runId: key, inputId: key, state: 'COMPLETE', laneSessionId: conversation.laneSessionId,
        principalId: 'foreign-subject', output: 'Foreign answer',
      }), 4, Date.now() + 1000 + index);
    }
    insert.run('malformed', 'plugin', 'target', 'unrelated:target', 'malformed', 'synthetic', '{', 1, Date.now() + 2000);
  })();
  const next = await f.conversation();
  expect(next.context).toContain('Live native question');
  expect(next.context).toContain('Live native answer');
  expect(next.context).not.toContain('Foreign answer');
  const history = (await migrationTool(next, 'partner_history', {})).value;
  expect(history).toEqual([{ question: 'Live native question', answer: 'Live native answer' }]);
});

it('byte-bounded archive pages and Unicode-safe source continuations reconstruct full text and facts', async (t) => {
  const f = await migrationFixture(); t.onTestFinished(f.close);
  const question = '🙂'.repeat(2100) + 'The final question fragment';
  const answer = 'a' + '🧑'.repeat(3200) + 'The final answer fragment';
  const facts = Array.from({ length: 20 }, (_, index) => 'Fact ' + index);
  const value = { ...f.snapshot, records: [
    { ...f.scope, sourceKey: 'long-turn', kind: 'history', chatId: f.channel.chatId, state: 'COMPLETE', question, answer },
    { ...f.scope, sourceKey: 'long-facts', kind: 'facts', facts },
    ...Array.from({ length: 12 }, (_, index) => ({ ...f.scope, sourceKey: 'escaped:' + index,
      kind: 'history', chatId: f.channel.chatId, state: 'COMPLETE', question: '\u0001'.repeat(3000), answer: '\u0002'.repeat(3000) })),
  ] };
  await f.migrate('apply', value);
  const conversation = await f.conversation();
  let continuation: Record<string, unknown> | null = { sourceId: value.sourceId, sourceKey: 'long-turn' };
  let actualQuestion = '', actualAnswer = '';
  while (continuation) {
    const page = await migrationTool(conversation, 'partner_migrated_data', { kind: 'history', ...continuation });
    expect(Buffer.byteLength(page.text)).toBeLessThan(49000);
    const record = page.value.records[0];
    actualQuestion += record.question; actualAnswer += record.answer;
    continuation = record.continuation;
  }
  expect(actualQuestion).toBe(question); expect(actualAnswer).toBe(answer);
  continuation = { sourceId: value.sourceId, sourceKey: 'long-facts' };
  const actualFacts: string[] = [];
  while (continuation) {
    const page = await migrationTool(conversation, 'partner_migrated_data', { kind: 'facts', ...continuation });
    actualFacts.push(...page.value.records[0].facts);
    continuation = page.value.records[0].continuation;
  }
  expect(actualFacts).toEqual(facts);
  const seen = new Set<string>();
  let offset: number | null = 0;
  while (offset !== null) {
    const page = await migrationTool(conversation, 'partner_migrated_data', { kind: 'history', offset });
    expect(Buffer.byteLength(page.text)).toBeLessThan(49000);
    for (const record of page.value.records) {
      expect(seen.has(record.sourceKey)).toBe(false); seen.add(record.sourceKey);
    }
    offset = page.value.nextOffset;
  }
  expect(seen.size).toBe(13);
  const query = await migrationTool(conversation, 'partner_migrated_data', { kind: 'history', query: 'final answer fragment' });
  expect(query.value.records[0].sourceKey).toBe('long-turn');
  await expect(migrationTool(conversation, 'partner_migrated_data', { kind: 'history', textOffset: 2000 })).rejects.toThrow('MIGRATION_DENIED');
});
