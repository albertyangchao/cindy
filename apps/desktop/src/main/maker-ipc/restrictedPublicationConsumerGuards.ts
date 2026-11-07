/**
 * Publication consumer proof CONTENT validation, not an issuer or IO gate.
 *
 * ABI: publication-consumer-guard-evidence-contract/v1, as emitted by
 * Bridge publication_consumer_guards.CoverageAuthority.read_current (d7788a1b).
 * Main must obtain `expected` from its real account-bound authority, never from
 * the child/Agent/proof itself. A valid result authenticates NO source, creates
 * NO READY state/admission, consumes NO challenge, and authorizes NO effects.
 * Main must separately consume its challenge and retain withAdmission/currentFence
 * plus the original native grant at stage and EVERY actual effect boundary.
 *
 * Input is an already-decoded data object. The transport must independently bound
 * the original JSON bytes and reject duplicate keys. This leaf bounds the UTF-8
 * JSON representation, rejects getters/proxies/non-data objects and returns only
 * finite codes. It has no IO, clock, cache, issuer/registration factory or writes.
 */
import { createHash } from 'node:crypto'
import { types } from 'node:util'

export const CONSUMER_GUARD_SCHEMA = 'publication-consumer-guard-evidence-contract/v1' as const
export const CONSUMER_GUARD_MAX_BYTES = 65_536
export const CONSUMER_GUARD_MAX_MEMBERS = 64
export const CONSUMER_GUARD_MAX_TTL_MS = 30_000

const ROLES = ['canonical-producer', 'generic-direct', 'worksheet-ci', 'worksheet-direct',
  'tracker-direct', 'shared-transaction', 'native-main-dispatch'] as const
const REQUIRED_GUARDED = ['canonical-producer', 'generic-direct', 'shared-transaction',
  'native-main-dispatch'] as const
const ADJACENT = ['bulk-report-sync', 'reserved-bundle', 'private-report-files',
  'external-subtree-publishers'] as const

export type ConsumerGuardRole = typeof ROLES[number]
export type ConsumerGuardMemberState = 'GUARDED' | 'NATIVE_NAMESPACE_DENIED' | 'RETIRED_FENCED'
export type ConsumerGuardLifecycle = 'UNSUPPORTED' | 'CLOSED_UNVERIFIED' | 'QUIESCING' |
  'READY' | 'REVOKED' | 'UNKNOWN'

export interface ConsumerGuardMember {
  readonly instanceId: string
  readonly entryId: ConsumerGuardRole
  readonly launchAuthorityId: string
  /** Actual current admission / exclusion / lawful-retirement receipt for state. */
  readonly admissionReceiptId: string
  readonly releaseGeneration: string
  readonly guardSourceIdentity: string
  readonly entryDefinitionDigest: string
  readonly state: ConsumerGuardMemberState
  readonly effectFenceRevision: number
}

export interface ConsumerGuardNamespaceExclusion {
  readonly entryId: typeof ADJACENT[number]
  readonly receiptId: string
  readonly entryDefinitionDigest: string
  readonly effectFenceRevision: number
}

/** Private Main observation, NOT a wire object to accept from the publisher.
 * Every member and exclusion must come from the actual closed registration and
 * current owner receipts. `oldGenerationFence` must refer to the actual measured
 * drain/fence receipt; Main must NOT derive it merely from a zero counter.
 *
 * v1's real producer uses four namespace exclusion records. Additional/unknown
 * writers or an inclusion-based alternative need a separately reviewed ABI, not
 * silent omission here. Main binds exclusions to this current fence/scope.
 */
export interface ConsumerGuardExpectation {
  readonly lifecycleState: ConsumerGuardLifecycle
  readonly issuerId: string
  readonly accountScopeRef: string
  readonly rootIdentity: string
  readonly releaseGeneration: string
  readonly releaseSequence: number
  readonly inventoryDigest: string
  readonly registrationSetDigest: string
  readonly coverageRevision: number
  readonly lifecycleSequence: number
  readonly challenge: string
  readonly closedEnrollment: boolean
  readonly members: readonly ConsumerGuardMember[]
  readonly oldGenerationAdmissions: number
  readonly unknownNativeEffects: number
  readonly fenceRef: string
  readonly oldGenerationFence: Readonly<{ disposition: 'DRAINED' | 'FENCED'; fenceRef: string }>
  readonly namespaceExclusions: readonly ConsumerGuardNamespaceExclusion[]
}

export type ConsumerGuardValidationCode =
  'COVERAGE_EVIDENCE_INVALID' | 'COVERAGE_EXPECTATION_INVALID' | 'COVERAGE_PROOF_LIMIT' |
  'COVERAGE_NOT_READY' | 'COVERAGE_ENROLLMENT_OPEN' | 'COVERAGE_CONTEXT_MISMATCH' |
  'COVERAGE_SEQUENCE_MISMATCH' | 'COVERAGE_CHALLENGE_MISMATCH' | 'COVERAGE_FRESHNESS_INVALID' |
  'COVERAGE_MEMBERSHIP_MISMATCH' | 'COVERAGE_CODE_ROLE_MISSING' | 'COVERAGE_MEMBER_INVALID' |
  'COVERAGE_MEMBER_BINDING_MISMATCH' | 'COVERAGE_REQUIRED_GUARD_MISSING' |
  'COVERAGE_UNRESOLVED' | 'COVERAGE_FENCE_UNPROVEN' | 'COVERAGE_NAMESPACE_UNPROVEN'

export type ConsumerGuardContentResult =
  Readonly<{ valid: true; kind: 'CONTENT_ONLY' }> |
  Readonly<{ valid: false; code: ConsumerGuardValidationCode }>

export class ConsumerGuardValidationError extends Error {
  readonly code: ConsumerGuardValidationCode
  constructor(code: ConsumerGuardValidationCode) {
    super(code)
    this.name = 'ConsumerGuardValidationError'
    this.code = code
  }
}

const EVIDENCE_KEYS = ['schema', 'issuerId', 'accountScopeRef', 'rootIdentity', 'releaseGeneration',
  'releaseSequence', 'inventoryDigest', 'registrationSetDigest', 'coverageRevision',
  'lifecycleSequence', 'issuedAt', 'expiresAt', 'challenge', 'closedEnrollment', 'members',
  'oldGenerationAdmissions', 'unknownNativeEffects', 'fenceRef'] as const
const EXPECTED_KEYS = ['lifecycleState', 'issuerId', 'accountScopeRef', 'rootIdentity',
  'releaseGeneration', 'releaseSequence', 'inventoryDigest', 'registrationSetDigest',
  'coverageRevision', 'lifecycleSequence', 'challenge', 'closedEnrollment', 'members',
  'oldGenerationAdmissions', 'unknownNativeEffects', 'fenceRef', 'oldGenerationFence',
  'namespaceExclusions'] as const
const MEMBER_KEYS = ['instanceId', 'entryId', 'launchAuthorityId', 'admissionReceiptId',
  'releaseGeneration', 'guardSourceIdentity', 'entryDefinitionDigest', 'state', 'effectFenceRevision'] as const
const EXCLUSION_KEYS = ['entryId', 'receiptId', 'entryDefinitionDigest', 'effectFenceRevision'] as const
const STATES: readonly string[] = ['GUARDED', 'NATIVE_NAMESPACE_DENIED', 'RETIRED_FENCED']
const LIFECYCLES: readonly string[] = ['UNSUPPORTED', 'CLOSED_UNVERIFIED', 'QUIESCING', 'READY', 'REVOKED', 'UNKNOWN']
type Data = null | string | number | boolean | Data[] | { [key: string]: Data }
type Row = { [key: string]: Data }

function fail(code: ConsumerGuardValidationCode): never { throw new ConsumerGuardValidationError(code) }
function need(ok: unknown, code: ConsumerGuardValidationCode): asserts ok { if (!ok) fail(code) }
function uint(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0)
}
function wellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const n = s.charCodeAt(i)
    if (n >= 0xd800 && n <= 0xdbff) {
      const low = s.charCodeAt(++i)
      if (!(low >= 0xdc00 && low <= 0xdfff)) return false
    } else if (n >= 0xdc00 && n <= 0xdfff) return false
  }
  return true
}
function opaque(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0 && v.length <= 512 && wellFormed(v) &&
    Buffer.byteLength(v, 'utf8') <= 512 && !/[\u0000-\u001f\u007f-\u009f]/u.test(v)
}
function hash(v: unknown): v is string { return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) }
function record(v: Data, keys: readonly string[], code: ConsumerGuardValidationCode): Row {
  need(v !== null && typeof v === 'object' && !Array.isArray(v), code)
  need(Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k)), code)
  return v
}

/** Take bounded inert snapshots; never invoke toJSON, getters or proxy traps. */
function snapshot(value: unknown, limit: number, code: ConsumerGuardValidationCode): Data {
  let nodes = 0, stringBytes = 0
  const stack = new Set<object>()
  function copy(v: unknown, depth: number): Data {
    need(++nodes <= 4096 && depth <= 6, 'COVERAGE_PROOF_LIMIT')
    if (v === null || typeof v === 'boolean') return v
    if (typeof v === 'string') {
      need(v.length <= limit, 'COVERAGE_PROOF_LIMIT')
      need(wellFormed(v), code)
      stringBytes += Buffer.byteLength(v, 'utf8')
      need(stringBytes <= limit, 'COVERAGE_PROOF_LIMIT')
      return v
    }
    if (typeof v === 'number') { need(uint(v), code); return v }
    need(typeof v === 'object' && !types.isProxy(v), code)
    need(!stack.has(v), code)
    const array = Array.isArray(v), proto = Object.getPrototypeOf(v)
    need(array ? proto === Array.prototype : proto === Object.prototype || proto === null, code)
    const descriptors = Object.getOwnPropertyDescriptors(v), keys = Reflect.ownKeys(descriptors)
    need(keys.length <= 65 && keys.every(k => typeof k === 'string'), code)
    stack.add(v)
    try {
      if (array) {
        const length = descriptors.length
        need(length && Object.hasOwn(length, 'value') && uint(length.value) && length.value <= 64, code)
        need(keys.length === length.value + 1, code)
        const result: Data[] = []
        for (let i = 0; i < length.value; i++) {
          const d = descriptors[String(i)]
          need(d && d.enumerable && Object.hasOwn(d, 'value'), code)
          result.push(copy(d.value, depth + 1))
        }
        return result
      }
      const result: Row = Object.create(null)
      for (const key of keys as string[]) {
        const d = descriptors[key]
        need(key.length <= 64 && wellFormed(key) && d.enumerable && Object.hasOwn(d, 'value'), code)
        result[key] = copy(d.value, depth + 1)
      }
      return result
    } finally { stack.delete(v) }
  }
  const result = copy(value, 0)
  need(Buffer.byteLength(JSON.stringify(result), 'utf8') <= limit, 'COVERAGE_PROOF_LIMIT')
  return result
}

/** Python's sorted(str) orders Unicode code points, not JS UTF-16 code units. */
function codePointOrder(a: string, b: string): number {
  const x = Array.from(a, c => c.codePointAt(0)!), y = Array.from(b, c => c.codePointAt(0)!)
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]
  return x.length - y.length
}
function registrationDigest(members: readonly Row[]): string {
  const ids = members.map(m => m.instanceId as string).sort(codePointOrder)
  return createHash('sha256').update(JSON.stringify(ids), 'utf8').digest('hex')
}
function members(value: Data, generation: string, root: string): Row[] {
  need(Array.isArray(value) && value.length > 0 && value.length <= CONSUMER_GUARD_MAX_MEMBERS,
    'COVERAGE_MEMBERSHIP_MISMATCH')
  const ids = new Set<string>(), roles = new Set<string>()
  const rows = value.map(item => {
    const m = record(item, MEMBER_KEYS, 'COVERAGE_MEMBER_INVALID')
    for (const k of ['instanceId', 'launchAuthorityId', 'admissionReceiptId']) need(opaque(m[k]), 'COVERAGE_MEMBER_INVALID')
    need(typeof m.entryId === 'string' && (ROLES as readonly string[]).includes(m.entryId), 'COVERAGE_MEMBER_INVALID')
    need(opaque(m.releaseGeneration) && m.releaseGeneration === generation && hash(m.guardSourceIdentity) &&
      m.guardSourceIdentity === root && hash(m.entryDefinitionDigest) && uint(m.effectFenceRevision) &&
      typeof m.state === 'string' && STATES.includes(m.state), 'COVERAGE_MEMBER_INVALID')
    need(!ids.has(m.instanceId as string), 'COVERAGE_MEMBERSHIP_MISMATCH')
    ids.add(m.instanceId as string); roles.add(m.entryId)
    if ((REQUIRED_GUARDED as readonly string[]).includes(m.entryId)) need(m.state === 'GUARDED', 'COVERAGE_REQUIRED_GUARD_MISSING')
    return m
  })
  need(ROLES.every(role => roles.has(role)), 'COVERAGE_CODE_ROLE_MISSING')
  return rows
}
function exclusions(value: Data): void {
  need(Array.isArray(value) && value.length === ADJACENT.length, 'COVERAGE_NAMESPACE_UNPROVEN')
  const seen = new Set<string>()
  for (const item of value) {
    const e = record(item, EXCLUSION_KEYS, 'COVERAGE_NAMESPACE_UNPROVEN')
    need(typeof e.entryId === 'string' && (ADJACENT as readonly string[]).includes(e.entryId) &&
      !seen.has(e.entryId) && opaque(e.receiptId) && hash(e.entryDefinitionDigest) &&
      uint(e.effectFenceRevision), 'COVERAGE_NAMESPACE_UNPROVEN')
    seen.add(e.entryId)
  }
}

/** All success means is that these two inert snapshots agree NOW by content. */
export function validatePublicationConsumerGuardEvidence(
  candidate: unknown, expected: unknown, now: unknown,
): ConsumerGuardContentResult {
  try {
    const e = record(snapshot(candidate, CONSUMER_GUARD_MAX_BYTES, 'COVERAGE_EVIDENCE_INVALID'),
      EVIDENCE_KEYS, 'COVERAGE_EVIDENCE_INVALID')
    const x = record(snapshot(expected, CONSUMER_GUARD_MAX_BYTES * 2, 'COVERAGE_EXPECTATION_INVALID'),
      EXPECTED_KEYS, 'COVERAGE_EXPECTATION_INVALID')
    need(e.schema === CONSUMER_GUARD_SCHEMA, 'COVERAGE_EVIDENCE_INVALID')
    need(typeof x.lifecycleState === 'string' && LIFECYCLES.includes(x.lifecycleState), 'COVERAGE_EXPECTATION_INVALID')
    need(x.lifecycleState === 'READY', 'COVERAGE_NOT_READY')
    need(x.closedEnrollment === true && e.closedEnrollment === true, 'COVERAGE_ENROLLMENT_OPEN')
    for (const k of ['issuerId', 'accountScopeRef', 'releaseGeneration', 'fenceRef']) {
      need(opaque(x[k]), 'COVERAGE_EXPECTATION_INVALID'); need(opaque(e[k]), 'COVERAGE_EVIDENCE_INVALID')
    }
    for (const k of ['rootIdentity', 'inventoryDigest', 'registrationSetDigest', 'challenge']) {
      need(hash(x[k]), 'COVERAGE_EXPECTATION_INVALID'); need(hash(e[k]), 'COVERAGE_EVIDENCE_INVALID')
    }
    for (const k of ['issuerId', 'accountScopeRef', 'rootIdentity', 'releaseGeneration', 'inventoryDigest'])
      need(e[k] === x[k], 'COVERAGE_CONTEXT_MISMATCH')
    need(e.challenge === x.challenge, 'COVERAGE_CHALLENGE_MISMATCH')
    need(e.fenceRef === x.fenceRef, 'COVERAGE_FENCE_UNPROVEN')
    for (const k of ['releaseSequence', 'coverageRevision', 'lifecycleSequence']) {
      need(uint(x[k]), 'COVERAGE_EXPECTATION_INVALID'); need(uint(e[k]), 'COVERAGE_EVIDENCE_INVALID')
      need(e[k] === x[k], 'COVERAGE_SEQUENCE_MISMATCH')
    }
    need(uint(now) && uint(e.issuedAt) && uint(e.expiresAt) && e.expiresAt > e.issuedAt &&
      e.expiresAt - e.issuedAt <= CONSUMER_GUARD_MAX_TTL_MS && e.issuedAt <= now && now < e.expiresAt,
    'COVERAGE_FRESHNESS_INVALID')
    for (const k of ['oldGenerationAdmissions', 'unknownNativeEffects']) {
      need(uint(e[k]) && uint(x[k]), 'COVERAGE_UNRESOLVED')
      need(e[k] === 0 && x[k] === 0, 'COVERAGE_UNRESOLVED')
    }
    const fence = record(x.oldGenerationFence, ['disposition', 'fenceRef'], 'COVERAGE_FENCE_UNPROVEN')
    need((fence.disposition === 'DRAINED' || fence.disposition === 'FENCED') &&
      opaque(fence.fenceRef) && fence.fenceRef === x.fenceRef, 'COVERAGE_FENCE_UNPROVEN')
    exclusions(x.namespaceExclusions)
    const trusted = members(x.members, x.releaseGeneration as string, x.rootIdentity as string)
    const observed = members(e.members, e.releaseGeneration as string, e.rootIdentity as string)
    need(x.registrationSetDigest === registrationDigest(trusted), 'COVERAGE_MEMBERSHIP_MISMATCH')
    need(e.registrationSetDigest === x.registrationSetDigest &&
      e.registrationSetDigest === registrationDigest(observed) && observed.length === trusted.length,
    'COVERAGE_MEMBERSHIP_MISMATCH')
    const byId = new Map(trusted.map(m => [m.instanceId, m]))
    for (const m of observed) {
      const match = byId.get(m.instanceId)
      need(match && MEMBER_KEYS.every(k => m[k] === match[k]), 'COVERAGE_MEMBER_BINDING_MISMATCH')
    }
    return Object.freeze({ valid: true, kind: 'CONTENT_ONLY' })
  } catch (error) {
    // Never return arbitrary error messages/objects or any input values.
    return Object.freeze({ valid: false, code: error instanceof ConsumerGuardValidationError ?
      error.code : 'COVERAGE_EVIDENCE_INVALID' })
  }
}

/** Precheck only: returning void is intentionally NOT an admission handle. */
export function assertConsumerGuards(candidate: unknown, expected: unknown, now: unknown): void {
  const result = validatePublicationConsumerGuardEvidence(candidate, expected, now)
  if (!result.valid) throw new ConsumerGuardValidationError(result.code)
}
