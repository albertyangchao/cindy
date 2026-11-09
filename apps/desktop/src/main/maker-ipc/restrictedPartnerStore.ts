import { digest as publicationDigest } from './restrictedPublicationProtocol.js';
import { and, eq, sql } from 'drizzle-orm';
import type { DbClient } from '../localDb/client/DbClient.js';
import { pluginTaskRequests } from '../localDb/schema.js';
import type {
  RestrictedPartnerClaim,
  RestrictedPartnerGrant,
} from './restrictedPartnerExecution.js';

type PublicationHistoryRow = {
  id: string;
  pluginId: string;
  operation: string;
  targetId: string;
  requestKey: string;
  fingerprint: string;
  payload: string;
  revision: number;
  createdAt: number;
};
type PublicationHistory = {
  identity: object;
  pluginId: string;
  accountScopeRef: string;
  rows: PublicationHistoryRow[];
  snapshot: string;
};
const publicationHistories = new WeakMap<object, PublicationHistory>();

/** A complete original-table read, held by Main. JSON cannot restore this handle. */
export function readPublicationHistoryReceipt(
  handle: object,
  identity: object,
  pluginId: string,
  accountScopeRef: string,
) {
  const value = publicationHistories.get(handle);
  if (!value || value.identity !== identity || value.pluginId !== pluginId ||
      value.accountScopeRef !== accountScopeRef)
    throw Error('PUBLICATION_OWNER_HISTORY_HANDLE_REQUIRED');
  return { rows: structuredClone(value.rows), sha256: publicationDigest(value.snapshot) };
}

/** Account-bound adapter over the existing receipt table. No new DB/schema migration. */
export function createRestrictedPartnerStore(db: DbClient, assertOwner: () => void) {
  const table = pluginTaskRequests;
  const read = async <T>(pluginId: string, target: string): Promise<T | undefined> => {
    assertOwner();
    const [row] = await db.drizzle
      .select()
      .from(table)
      .where(
        and(
          eq(table.operation, 'target'),
          eq(table.pluginId, pluginId),
          eq(table.targetId, target),
        ),
      )
      .limit(1);
    assertOwner();
    return row ? (JSON.parse(row.payload) as T) : undefined;
  };
  const nativePublicationPredicate = (pluginId: string) => and(
    eq(table.pluginId, pluginId),
    sql`(${table.id} LIKE 'native-publication:%' OR ${table.targetId} LIKE 'restricted:publication:%' OR (CASE WHEN json_valid(${table.payload}) THEN json_extract(${table.payload}, '$.schema') ELSE NULL END) = 'native-publication-action/v1')`,
  );
  const unresolvedAdmissionPredicate = (pluginId: string, accountScopeRef: string) => and(
    eq(table.operation, 'target'),
    eq(table.pluginId, pluginId),
    sql`${table.targetId} LIKE ${`publication-coverage:${accountScopeRef}:%`}`,
    sql`((json_extract(${table.payload}, '$.schema') IN ('publication-coverage-admission/v1', 'publication-managed-job/v1', 'publication-ci-runner-effect/v1')
      AND coalesce(json_extract(${table.payload}, '$.state'), 'UNKNOWN') <> 'COMPLETE')
      OR (json_extract(${table.payload}, '$.schema') = 'publication-original-owner-listener/v1'
        AND json_extract(${table.payload}, '$.state') IN ('PARKING_UNKNOWN', 'OBSERVING', 'RESUMING_UNKNOWN'))
      OR (json_extract(${table.payload}, '$.schema') = 'publication-main-source-operation/v1'
        AND json_extract(${table.payload}, '$.state') IN ('PARKING_UNKNOWN', 'PARKED', 'RESUMING_UNKNOWN')))`,
  );
  const ownerHistoryPredicate = (pluginId: string, accountScopeRef: string) => and(
    eq(table.pluginId, pluginId),
    // Include malformed and wrong-operation rows in the original namespace:
    // they must fail the source read, rather than disappear from a census.
    sql`(${table.targetId} LIKE ${`publication-coverage:${accountScopeRef}:%`} OR ${table.id} LIKE ${`publication-coverage:${pluginId}:${accountScopeRef}:%`})`,
  );
  const historyColumns = (rows: PublicationHistoryRow[]) => JSON.stringify(rows.map(row => [
    row.id, row.pluginId, row.operation, row.targetId, row.requestKey,
    row.fingerprint, row.payload, row.revision, row.createdAt,
  ]));
  const ownerHistoryFacts = async (pluginId: string, accountScopeRef: string) => {
    assertOwner();
    if (!/^[a-f0-9]{64}$/.test(accountScopeRef))
      throw Error('PUBLICATION_OWNER_HISTORY_SCOPE');
    const rows = await db.drizzle.select().from(table)
      .where(ownerHistoryPredicate(pluginId, accountScopeRef)).orderBy(table.id);
    assertOwner();
    for (const row of rows) {
      const prefix = `publication-coverage:${accountScopeRef}:`;
      const key = row.targetId.startsWith(prefix) ? row.targetId.slice(prefix.length) : '';
      if (!/^[a-f0-9]{64}$/.test(key) || row.operation !== 'target' ||
          row.pluginId !== pluginId || row.requestKey !== key ||
          row.id !== `publication-coverage:${pluginId}:${accountScopeRef}:${key}` ||
          row.fingerprint !== accountScopeRef || !Number.isSafeInteger(row.revision) ||
          row.revision < 1 || !Number.isSafeInteger(row.createdAt) || row.createdAt < 0 ||
          Buffer.byteLength(row.payload) > 65536)
        throw Error('PUBLICATION_OWNER_HISTORY_UNKNOWN');
      try {
        const value: unknown = JSON.parse(row.payload);
        if (!value || typeof value !== 'object' || Array.isArray(value))
          throw Error('schema');
      } catch {
        throw Error('PUBLICATION_OWNER_HISTORY_UNKNOWN');
      }
    }
    const snapshot = historyColumns(rows);
    if (Buffer.byteLength(snapshot) > 1048576)
      throw Error('PUBLICATION_OWNER_HISTORY_LIMIT');
    return { rows, snapshot };
  };
  const nativePublicationFacts = async (pluginId: string) => {
    assertOwner();
    const rows = await db.drizzle
      .select()
      .from(table)
      .where(nativePublicationPredicate(pluginId))
      .orderBy(table.id);
    assertOwner();
    let unknown = 0;
    const deny = (): never => {
      throw Error('PUBLICATION_NATIVE_EFFECT_FACTS_UNKNOWN');
    };
    const states = [
      'PREPARED_NO_REMOTE_EFFECT',
      'DISPATCHING_UNKNOWN',
      'APPLIED_VERIFIED',
      'REJECTED_NO_DISPATCH',
      'UNKNOWN',
    ];
    const phases = ['remote-staging-prepare', 'remote-staging-upload', 'remote-transaction'];
    for (const row of rows) {
      let a: any;
      try {
        a = JSON.parse(row.payload);
      } catch {
        deny();
      }
      if (
        !a ||
        a.schema !== 'native-publication-action/v1' ||
        a.pluginId !== pluginId ||
        row.operation !== 'target' ||
        typeof a.nativeActionId !== 'string' ||
        !/^[a-f0-9-]{36}$/.test(a.nativeActionId) ||
        row.id !== 'native-publication:' + a.nativeActionId ||
        !states.includes(a.state) ||
        a.actionRevision !== 1 ||
        !Number.isSafeInteger(a.stateRevision) ||
        a.stateRevision < 1 ||
        a.stateRevision !== row.revision ||
        row.fingerprint !== publicationDigest(a)
      )
        deny();
      const bindings = [
        a.principalId,
        a.partnerId,
        a.runId,
        a.sourceOutputMessageId,
        a.completedOutputSha256,
      ];
      if (
        bindings.some((v) => typeof v !== 'string' || !v || Buffer.byteLength(v) > 512) ||
        !/^[a-f0-9]{64}$/.test(a.completedOutputSha256)
      )
        deny();
      const target =
        'restricted:publication:' + publicationDigest([pluginId, ...bindings, 'PUBLIC_RELEASE']);
      if (
        row.targetId !== target ||
        row.requestKey !== target ||
        !Array.isArray(a.effects) ||
        a.effects.length > 3 ||
        a.effects.some((v: any, i: number) => v !== phases[i])
      )
        deny();
      if (
        ['PREPARED_NO_REMOTE_EFFECT', 'REJECTED_NO_DISPATCH'].includes(a.state) &&
        a.effects.length !== 0
      )
        deny();
      if (
        a.state === 'APPLIED_VERIFIED' &&
        (a.effects.length !== 3 || !/^[a-f0-9]{64}$/.test(a.receiptSha256))
      )
        deny();
      if (a.state === 'UNKNOWN' || a.state === 'DISPATCHING_UNKNOWN') unknown++;
    }
    assertOwner();
    return { unknown, snapshot: JSON.stringify(rows.map(row => [
      row.id, row.pluginId, row.operation, row.targetId, row.requestKey,
      row.fingerprint, row.payload, row.revision, row.createdAt,
    ])) };
  };
  return {
    /** Main-private coverage receipts share this account's existing table. No public SQL port. */
    consumerGuardReceiptIdentity: db,
    /** No time window, LIMIT, latest-only selection, or removal of terminal rows. */
    async capturePublicationOwnerHistory(pluginId: string, accountScopeRef: string) {
      const facts = await ownerHistoryFacts(pluginId, accountScopeRef);
      const handle = Object.freeze(Object.create(null)) as object;
      publicationHistories.set(handle, { identity: db, pluginId, accountScopeRef, ...facts });
      return handle;
    },
    async assertPublicationOwnerHistoryCurrent(handle: object, pluginId: string, accountScopeRef: string) {
      readPublicationHistoryReceipt(handle, db, pluginId, accountScopeRef);
      const expected = publicationHistories.get(handle)!;
      const actual = await ownerHistoryFacts(pluginId, accountScopeRef);
      if (actual.snapshot !== expected.snapshot)
        throw Error('PUBLICATION_OWNER_HISTORY_CHANGED');
    },
    /** Read only actual native publication action records in this owner's account DB. */
    async unknownNativePublicationEffects(pluginId: string): Promise<number> {
      return (await nativePublicationFacts(pluginId)).unknown;
    },
    async unresolvedConsumerGuardAdmissions(pluginId: string, accountScopeRef: string) {
      assertOwner();
      const [row] = await db.drizzle
        .select({ count: sql<number>`count(*)` })
        .from(table)
        .where(unresolvedAdmissionPredicate(pluginId, accountScopeRef));
      assertOwner();
      const count = Number(row?.count);
      if (!Number.isSafeInteger(count) || count < 0)
        throw Error('PUBLICATION_COVERAGE_RECEIPT_UNKNOWN');
      return count;
    },
    async readConsumerGuardReceipt(pluginId: string, accountScopeRef: string, key: string) {
      assertOwner();
      const target = `publication-coverage:${accountScopeRef}:${key}`;
      const [row] = await db.drizzle
        .select()
        .from(table)
        .where(
          and(
            eq(table.operation, 'target'),
            eq(table.pluginId, pluginId),
            eq(table.targetId, target),
          ),
        )
        .limit(1);
      assertOwner();
      return row ? { revision: row.revision, payload: row.payload } : undefined;
    },
    async compareAndSwapConsumerGuardReceipt(
      pluginId: string,
      accountScopeRef: string,
      key: string,
      previous: { revision: number; payload: string } | undefined,
      payload: string,
      requirePublicationDrained = false,
      requiredOwnerHistory?: object,
    ) {
      assertOwner();
      if (
        !/^[a-f0-9]{64}$/.test(accountScopeRef) ||
        !/^[a-f0-9]{64}$/.test(key) ||
        Buffer.byteLength(payload) > 65536 ||
        typeof requirePublicationDrained !== 'boolean' ||
        (requirePublicationDrained && !previous) ||
        (requiredOwnerHistory !== undefined && !previous) ||
        (previous && (!Number.isSafeInteger(previous.revision) || previous.revision < 1))
      )
        throw Error('PUBLICATION_COVERAGE_RECEIPT_INVALID');
      const target = `publication-coverage:${accountScopeRef}:${key}`;
      const nextRevision = (previous?.revision ?? 0) + 1;
      if (!Number.isSafeInteger(nextRevision)) throw Error('PUBLICATION_COVERAGE_RECEIPT_INVALID');
      let drained: ReturnType<typeof and>;
      let historyUnchanged: ReturnType<typeof and>;
      if (requiredOwnerHistory !== undefined) {
        readPublicationHistoryReceipt(requiredOwnerHistory, db, pluginId, accountScopeRef);
        const facts = publicationHistories.get(requiredOwnerHistory)!;
        historyUnchanged = sql`(SELECT coalesce(json_group_array(json(owner_record)), '[]') FROM
          (SELECT json_array(${table.id}, ${table.pluginId}, ${table.operation}, ${table.targetId},
            ${table.requestKey}, ${table.fingerprint}, ${table.payload}, ${table.revision}, ${table.createdAt}) AS owner_record
            FROM ${table} WHERE ${ownerHistoryPredicate(pluginId, accountScopeRef)} ORDER BY ${table.id})) = ${facts.snapshot}`;
      }
      if (requirePublicationDrained) {
        const facts = await nativePublicationFacts(pluginId);
        if (facts.unknown !== 0) return false;
        // The UPDATE must observe the same complete native rows that passed
        // validation, not just a zero count or a caller-supplied state label.
        // An inserted, deleted or changed row (including malformed/APPLIED
        // records) makes this predicate false before the receipt can advance.
        drained = and(
          sql`NOT EXISTS (SELECT 1 FROM ${table} WHERE ${unresolvedAdmissionPredicate(pluginId, accountScopeRef)})`,
          sql`(SELECT coalesce(json_group_array(json(native_record)), '[]') FROM
            (SELECT json_array(${table.id}, ${table.pluginId}, ${table.operation}, ${table.targetId},
              ${table.requestKey}, ${table.fingerprint}, ${table.payload}, ${table.revision}, ${table.createdAt}) AS native_record
              FROM ${table} WHERE ${nativePublicationPredicate(pluginId)} ORDER BY ${table.id})) = ${facts.snapshot}`,
        );
      }
      assertOwner();
      const result = previous
        ? await db.drizzle
            .update(table)
            .set({ payload, revision: nextRevision })
            .where(
              and(
                eq(table.operation, 'target'),
                eq(table.pluginId, pluginId),
                eq(table.targetId, target),
                eq(table.revision, previous.revision),
                eq(table.payload, previous.payload),
                drained,
                historyUnchanged,
              ),
            )
            .returning({ id: table.id })
        : await db.drizzle
            .insert(table)
            .values({
              id: `publication-coverage:${pluginId}:${accountScopeRef}:${key}`,
              pluginId,
              operation: 'target',
              targetId: target,
              requestKey: key,
              fingerprint: accountScopeRef,
              payload,
              revision: nextRevision,
              createdAt: Date.now(),
            })
            .onConflictDoNothing()
            .returning({ id: table.id });
      assertOwner();
      return result.length === 1;
    },
    readGrant: (pluginId: string, grantId: string) =>
      read<RestrictedPartnerGrant>(pluginId, `restricted:grant:${grantId}`),
    /** Main owner UI only; the production caller must validate local consent + exact existing partner first. */
    async compareAndSwapGrant(grant: RestrictedPartnerGrant, expectedRevision: number) {
      assertOwner();
      if (
        !Number.isSafeInteger(expectedRevision) ||
        expectedRevision < 0 ||
        grant.revision !== expectedRevision + 1
      )
        throw new Error('RESTRICTED_PARTNER_GRANT_CONFLICT');
      const targetId = `restricted:grant:${grant.id}`;
      if (expectedRevision === 0) {
        const rows = await db.drizzle
          .insert(table)
          .values({
            id: `restricted-grant:${grant.id}`,
            pluginId: grant.pluginId,
            operation: 'target',
            targetId,
            requestKey: grant.id,
            fingerprint: grant.personaSha256,
            payload: JSON.stringify(grant),
            revision: grant.revision,
            createdAt: Date.now(),
          })
          .onConflictDoNothing()
          .returning({ id: table.id });
        assertOwner();
        return rows.length === 1;
      }
      const rows = await db.drizzle
        .update(table)
        .set({ payload: JSON.stringify(grant), revision: grant.revision })
        .where(
          and(
            eq(table.operation, 'target'),
            eq(table.pluginId, grant.pluginId),
            eq(table.targetId, targetId),
            eq(table.revision, expectedRevision),
          ),
        )
        .returning({ id: table.id });
      assertOwner();
      return rows.length === 1;
    },
    async control(grant: RestrictedPartnerGrant, enabled: boolean) {
      assertOwner();
      const next = { ...grant, dispatchEpoch: grant.dispatchEpoch + 1, dispatchEnabled: enabled };
      const rows = await db.drizzle
        .update(table)
        .set({ payload: JSON.stringify(next) })
        .where(
          and(
            eq(table.operation, 'target'),
            eq(table.pluginId, grant.pluginId),
            eq(table.targetId, `restricted:grant:${grant.id}`),
            eq(table.revision, grant.revision),
            eq(table.payload, JSON.stringify(grant)),
          ),
        )
        .returning({ id: table.id });
      assertOwner();
      return rows.length === 1 ? next : undefined;
    },
    async byRun(pluginId: string, runId: string) {
      assertOwner();
      const [row] = await db.drizzle
        .select()
        .from(table)
        .where(
          and(
            eq(table.id, `restricted-run:${runId}`),
            eq(table.pluginId, pluginId),
            eq(table.operation, 'target'),
          ),
        )
        .limit(1);
      assertOwner();
      return row ? (JSON.parse(row.payload) as RestrictedPartnerClaim) : undefined;
    },
    async unresolvedCount(pluginId: string, principalId: string) {
      assertOwner();
      const [row] = await db.drizzle
        .select({ count: sql<number>`count(*)` })
        .from(table)
        .where(
          and(
            eq(table.pluginId, pluginId),
            eq(table.operation, 'target'),
            sql`${table.targetId} LIKE 'restricted:input:%'`,
            sql`json_extract(${table.payload},'$.principalId') = ${principalId}`,
            sql`coalesce(json_extract(${table.payload},'$.state'),'UNKNOWN') <> 'COMPLETE'`,
          ),
        );
      assertOwner();
      const count = Number(row?.count);
      if (!Number.isSafeInteger(count) || count < 0)
        throw Error('RESTRICTED_PARTNER_RESULT_CONFLICT');
      return count;
    },
    readClaim: (pluginId: string, inputId: string) =>
      read<RestrictedPartnerClaim>(pluginId, `restricted:input:${inputId}`),
    async reserve(claim: RestrictedPartnerClaim) {
      assertOwner();
      if (
        claim.state !== 'UNKNOWN' ||
        claim.output !== undefined ||
        claim.outputMessageId !== undefined
      )
        throw new Error('RESTRICTED_PARTNER_CLAIM_INVALID');
      const result = await db.exec(
        `INSERT INTO plugin_task_requests
        (id,plugin_id,operation,target_id,request_key,fingerprint,payload,revision,created_at)
        SELECT ?,?,'target',?,?,?,?,1,?
        WHERE NOT EXISTS (SELECT 1 FROM plugin_task_requests u WHERE u.operation='target'
          AND u.plugin_id=? AND u.target_id LIKE 'restricted:input:%' AND json_extract(u.payload,'$.principalId')=?
          AND COALESCE(json_extract(u.payload,'$.state'),'UNKNOWN') <> 'COMPLETE'
          AND NOT EXISTS (SELECT 1 FROM plugin_task_requests h WHERE h.plugin_id=u.plugin_id AND h.operation='target'
            AND h.target_id='restricted:launch-held:' || json_extract(u.payload,'$.inputId')
            AND json_extract(h.payload,'$.schema')='restricted-native-launch-hold/v1'
            AND json_extract(h.payload,'$.sourceId')=u.id AND json_extract(h.payload,'$.sourcePayload')=u.payload
            AND json_extract(h.payload,'$.sourceRevision')=u.revision
            AND json_extract(h.payload,'$.sourceCreatedAt')=u.created_at
            AND json_extract(h.payload,'$.principalId')=json_extract(u.payload,'$.principalId')))
        AND NOT EXISTS (SELECT 1 FROM plugin_task_requests h WHERE h.plugin_id=? AND h.operation='target'
          AND h.target_id LIKE 'restricted:launch-held:%'
          AND json_extract(h.payload,'$.schema')='restricted-native-launch-hold/v1'
          AND json_extract(h.payload,'$.principalId')=?
          AND (json_extract(h.payload,'$.inputId')=? OR
            (json_extract(h.payload,'$.connectionId')=? AND json_extract(h.payload,'$.eventId')=?)))
        ON CONFLICT DO NOTHING`,
        [
          `restricted-run:${claim.runId}`,
          claim.pluginId,
          `restricted:input:${claim.inputId}`,
          claim.inputId,
          claim.inputSha256,
          JSON.stringify(claim),
          Date.now(),
          claim.pluginId,
          claim.principalId,
          claim.pluginId,
          claim.principalId,
          claim.inputId,
          claim.channel?.connectionId ?? null,
          claim.channel?.eventId ?? null,
        ],
      );
      assertOwner();
      return result.changes === 1;
    },
    async recordExecution(runId: string, nativeThreadId: string, routeFingerprint: string) {
      assertOwner();
      const id = `restricted-run:${runId}`;
      const [row] = await db.drizzle
        .select()
        .from(table)
        .where(and(eq(table.id, id), eq(table.operation, 'target')))
        .limit(1);
      assertOwner();
      if (!row || row.revision !== 1) return false;
      const claim = JSON.parse(row.payload) as RestrictedPartnerClaim;
      if (claim.state !== 'UNKNOWN' || claim.nativeThreadId !== undefined || claim.runId !== runId)
        return false;
      const rows = await db.drizzle
        .update(table)
        .set({
          payload: JSON.stringify({ ...claim, nativeThreadId, routeFingerprint }),
          revision: 2,
        })
        .where(and(eq(table.id, id), eq(table.operation, 'target'), eq(table.revision, 1)))
        .returning({ id: table.id });
      assertOwner();
      return rows.length === 1;
    },
    async recordResult(
      runId: string,
      outputMessageId: string,
      output: string,
      assets?: import('./restrictedPartnerExecution.js').RestrictedOutputAsset[],
      laneSessionId?: string,
    ) {
      assertOwner();
      const id = `restricted-run:${runId}`;
      const [row] = await db.drizzle
        .select()
        .from(table)
        .where(and(eq(table.id, id), eq(table.operation, 'target')))
        .limit(1);
      assertOwner();
      if (!row) return false;
      const claim = JSON.parse(row.payload) as RestrictedPartnerClaim;
      if (
        claim.runId !== runId ||
        claim.state !== 'UNKNOWN' ||
        row.revision !== 2 ||
        !claim.nativeThreadId
      )
        return false;
      const rows = await db.drizzle
        .update(table)
        .set({
          payload: JSON.stringify({
            ...claim,
            outputMessageId,
            output,
            ...(assets?.length ? { assets } : {}),
            ...(laneSessionId ? { laneSessionId } : {}),
          }),
          revision: 3,
        })
        .where(and(eq(table.id, id), eq(table.operation, 'target'), eq(table.revision, 2)))
        .returning({ id: table.id });
      assertOwner();
      return rows.length === 1;
    },
    async complete(runId: string) {
      assertOwner();
      const id = `restricted-run:${runId}`;
      const [row] = await db.drizzle
        .select()
        .from(table)
        .where(and(eq(table.id, id), eq(table.operation, 'target')))
        .limit(1);
      assertOwner();
      if (!row || row.revision !== 3) return false;
      const claim = JSON.parse(row.payload) as RestrictedPartnerClaim;
      if (
        claim.runId !== runId ||
        claim.state !== 'UNKNOWN' ||
        !claim.outputMessageId ||
        typeof claim.output !== 'string'
      )
        return false;
      const rows = await db.drizzle
        .update(table)
        .set({ payload: JSON.stringify({ ...claim, state: 'COMPLETE' }), revision: 4 })
        .where(and(eq(table.id, id), eq(table.operation, 'target'), eq(table.revision, 3)))
        .returning({ id: table.id });
      assertOwner();
      return rows.length === 1;
    },
  };
}
