import { digest as publicationDigest } from './restrictedPublicationProtocol.js';
import { and, eq, sql } from 'drizzle-orm';
import type { DbClient } from '../localDb/client/DbClient.js';
import { pluginTaskRequests } from '../localDb/schema.js';
import type {
  RestrictedPartnerClaim,
  RestrictedPartnerGrant,
} from './restrictedPartnerExecution.js';

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
  return {
    /** Main-private coverage receipts share this account's existing table. No public SQL port. */
    consumerGuardReceiptIdentity: db,
    /** Read only actual native publication action records in this owner's account DB. */
    async unknownNativePublicationEffects(pluginId: string): Promise<number> {
      assertOwner();
      const rows = await db.drizzle
        .select()
        .from(table)
        .where(
          and(
            eq(table.pluginId, pluginId),
            sql`(${table.id} LIKE 'native-publication:%' OR ${table.targetId} LIKE 'restricted:publication:%' OR (CASE WHEN json_valid(${table.payload}) THEN json_extract(${table.payload}, '$.schema') ELSE NULL END) = 'native-publication-action/v1')`,
          ),
        );
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
      return unknown;
    },
    async unresolvedConsumerGuardAdmissions(pluginId: string, accountScopeRef: string) {
      assertOwner();
      const [row] = await db.drizzle
        .select({ count: sql<number>`count(*)` })
        .from(table)
        .where(
          and(
            eq(table.operation, 'target'),
            eq(table.pluginId, pluginId),
            sql`${table.targetId} LIKE ${`publication-coverage:${accountScopeRef}:%`}`,
            sql`json_extract(${table.payload}, '$.schema') IN ('publication-coverage-admission/v1', 'publication-managed-job/v1')`,
            sql`coalesce(json_extract(${table.payload}, '$.state'), 'UNKNOWN') <> 'COMPLETE'`,
          ),
        );
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
    ) {
      assertOwner();
      if (
        !/^[a-f0-9]{64}$/.test(accountScopeRef) ||
        !/^[a-f0-9]{64}$/.test(key) ||
        Buffer.byteLength(payload) > 65536 ||
        (previous && (!Number.isSafeInteger(previous.revision) || previous.revision < 1))
      )
        throw Error('PUBLICATION_COVERAGE_RECEIPT_INVALID');
      const target = `publication-coverage:${accountScopeRef}:${key}`;
      const nextRevision = (previous?.revision ?? 0) + 1;
      if (!Number.isSafeInteger(nextRevision)) throw Error('PUBLICATION_COVERAGE_RECEIPT_INVALID');
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
        WHERE NOT EXISTS (SELECT 1 FROM plugin_task_requests WHERE operation='target'
          AND plugin_id=? AND target_id LIKE 'restricted:input:%' AND json_extract(payload,'$.principalId')=?
          AND COALESCE(json_extract(payload,'$.state'),'UNKNOWN') <> 'COMPLETE')
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
