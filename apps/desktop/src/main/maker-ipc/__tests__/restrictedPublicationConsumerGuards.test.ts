/** Pure synthetic contract tests. No Cindy/DB/providers/network/production paths.
 * Default runner is the Host's Vitest. The explicit standalone switch runs the
 * SAME assertions on Node's real test runner when the full Host dependencies are
 * unavailable; it is not a fake Vitest shim or an application runtime switch.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  assertConsumerGuards, validatePublicationConsumerGuardEvidence as validate,
  ConsumerGuardValidationError, CONSUMER_GUARD_SCHEMA, CONSUMER_GUARD_MAX_BYTES,
  type ConsumerGuardExpectation, type ConsumerGuardValidationCode,
} from '../restrictedPublicationConsumerGuards.js'

const runnerName = process.env.CINDY_CONSUMER_GUARD_NODE_TEST === '1' ? 'node:test' : 'vitest'
const { test } = await import(runnerName) as { test: (name: string, fn: () => void) => unknown }
const NOW = 1_800_000_000_001
const roles = ['canonical-producer', 'generic-direct', 'worksheet-ci', 'worksheet-direct',
  'tracker-direct', 'shared-transaction', 'native-main-dispatch'] as const
const adjacent = ['bulk-report-sync', 'reserved-bundle', 'private-report-files', 'external-subtree-publishers'] as const
// Tests intentionally mutate untrusted data of many shapes.
type Input = Record<string, any>
function sha(value: unknown): string { return createHash('sha256').update(JSON.stringify(value)).digest('hex') }
function clone<T>(value: T): T { return structuredClone(value) }
function member(index: number): Input {
  return { instanceId: `instance-${index}`, entryId: roles[index % 7], launchAuthorityId: 'owner-launch',
    admissionReceiptId: `receipt-${index}`, releaseGeneration: 'release-原样', guardSourceIdentity: 'a'.repeat(64),
    entryDefinitionDigest: 'b'.repeat(64), state: 'GUARDED', effectFenceRevision: 2 }
}
function expectation(e: Input): Input {
  const { schema, issuedAt, expiresAt, ...fields } = clone(e)
  return { ...fields, lifecycleState: 'READY', oldGenerationFence: { disposition: 'DRAINED', fenceRef: e.fenceRef },
    namespaceExclusions: adjacent.map(entryId => ({ entryId, receiptId: `exclude-${entryId}`,
      entryDefinitionDigest: 'c'.repeat(64), effectFenceRevision: 2 })) }
}
function fixture(count = 7): { e: Input; x: Input } {
  const e: Input = { schema: CONSUMER_GUARD_SCHEMA, issuerId: 'actual-owner', accountScopeRef: 'original-account',
    rootIdentity: 'a'.repeat(64), releaseGeneration: 'release-原样', releaseSequence: 5,
    inventoryDigest: 'c'.repeat(64), registrationSetDigest: '', coverageRevision: 8, lifecycleSequence: 5,
    issuedAt: NOW - 1, expiresAt: NOW + 29_999, challenge: 'd'.repeat(64), closedEnrollment: true,
    members: Array.from({ length: count }, (_, i) => member(i)), oldGenerationAdmissions: 0,
    unknownNativeEffects: 0, fenceRef: 'real-current-fence' }
  e.registrationSetDigest = sha(e.members.map((m: Input) => m.instanceId).sort())
  return { e, x: expectation(e) }
}
function valid(e: unknown, x: unknown, now: unknown = NOW): void {
  assert.deepEqual(validate(e, x, now), { valid: true, kind: 'CONTENT_ONLY' })
  assert.equal(assertConsumerGuards(e, x, now), undefined)
}
function invalid(e: unknown, x: unknown, code?: ConsumerGuardValidationCode, now: unknown = NOW): void {
  const result = validate(e, x, now)
  assert.equal(result.valid, false)
  assert.ok(!result.valid)
  if (code) assert.equal(result.code, code)
  assert.deepEqual(Object.keys(result).sort(), ['code', 'valid'])
  assert.throws(() => assertConsumerGuards(e, x, now), (error: unknown) =>
    error instanceof ConsumerGuardValidationError && error.message === result.code && error.code === result.code)
}

// Readiness and proof freshness are content claims only, never authentication.
test('v1 exact observed fields pass only as CONTENT_ONLY; assert returns no permit', () => {
  const { e, x } = fixture(); valid(e, x)
})
test('multiple registered instances per role are supported', () => { const { e, x } = fixture(12); valid(e, x) })
test('member ordering is not authority; full per-instance bindings are retained', () => {
  const { e, x } = fixture(12); e.members.reverse(); valid(e, x)
})
test('two identical bytes/definitions do not merge distinct instance receipts', () => {
  const { e, x } = fixture(8); valid(e, x)
  e.members[7].admissionReceiptId = e.members[0].admissionReceiptId
  invalid(e, x, 'COVERAGE_MEMBER_BINDING_MISMATCH')
})
test('no input mutation, cached validity, challenge consumption or issuer state', () => {
  const { e, x } = fixture(), before = clone({ e, x })
  valid(e, x); valid(e, x); assert.deepEqual({ e, x }, before)
  x.fenceRef = 'later-fence'; invalid(e, x, 'COVERAGE_FENCE_UNPROVEN')
})
test('frozen and null-prototype plain data can be validated without writes', () => {
  const { e, x } = fixture(); Object.setPrototypeOf(e, null)
  for (const m of e.members) Object.freeze(m)
  Object.freeze(e.members); Object.freeze(e); Object.freeze(x); valid(e, x)
})
for (const state of ['UNSUPPORTED', 'CLOSED_UNVERIFIED', 'QUIESCING', 'REVOKED', 'UNKNOWN']) {
  test(`trusted authority ${state} cannot pass even with well-formed evidence`, () => {
    const { e, x } = fixture(); x.lifecycleState = state; invalid(e, x, 'COVERAGE_NOT_READY')
  })
}
for (const field of Object.keys(fixture().e)) {
  test(`missing required evidence field ${field} is not defaulted`, () => {
    const { e, x } = fixture(); delete e[field]; invalid(e, x, 'COVERAGE_EVIDENCE_INVALID')
  })
}
for (const field of Object.keys(fixture().x)) {
  test(`missing trusted context field ${field} cannot establish readiness`, () => {
    const { e, x } = fixture(); delete x[field]; invalid(e, x, 'COVERAGE_EXPECTATION_INVALID')
  })
}
for (const field of ['issuerId', 'accountScopeRef', 'rootIdentity', 'releaseGeneration', 'inventoryDigest']) {
  test(`wrong ${field} is rejected against independent expectation`, () => {
    const { e, x } = fixture(); e[field] = field.includes('Digest') || field === 'rootIdentity' ? 'f'.repeat(64) : 'other'
    invalid(e, x, 'COVERAGE_CONTEXT_MISMATCH')
  })
}
for (const field of ['releaseSequence', 'coverageRevision', 'lifecycleSequence']) {
  for (const direction of [-1, 1, 9]) test(`${field} rollback/gap ${direction} is rejected`, () => {
    const { e, x } = fixture(); e[field] += direction; invalid(e, x, 'COVERAGE_SEQUENCE_MISMATCH')
  })
}
for (const value of [true, '5', null, -1, -0, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  test(`unsafe numeric type/value ${String(value)} (${typeof value}) is rejected`, () => {
    const { e, x } = fixture(); e.releaseSequence = value; invalid(e, x)
  })
}
test('safe integer upper bound is exact, no arithmetic overflow coerces it', () => {
  const { e, x } = fixture(); e.releaseSequence = x.releaseSequence = Number.MAX_SAFE_INTEGER; valid(e, x)
})
test('challenge mismatch and non-lowercase challenge reject', () => {
  const { e, x } = fixture(); e.challenge = 'e'.repeat(64); invalid(e, x, 'COVERAGE_CHALLENGE_MISMATCH')
  e.challenge = 'D'.repeat(64); invalid(e, x, 'COVERAGE_EVIDENCE_INVALID')
})
for (const [label, update, now] of [
  ['expired at exact boundary', { expiresAt: NOW }, NOW],
  ['issued in future', { issuedAt: NOW + 1 }, NOW],
  ['TTL exceeds thirty seconds', { expiresAt: NOW + 30_000 }, NOW],
  ['zero TTL', { expiresAt: NOW - 1 }, NOW],
  ['negative TTL', { expiresAt: NOW - 2 }, NOW],
  ['time not observed', {}, undefined],
  ['boolean clock', {}, true],
] as const) test(label, () => {
  const { e, x } = fixture(); Object.assign(e, update)
  // Do not let the helper's default turn undefined into an observed time.
  assert.equal(validate(e, x, now).valid, false)
})
test('exact issuance and last unexpired millisecond accepted; expiry then rejects', () => {
  const { e, x } = fixture(); valid(e, x, e.issuedAt); valid(e, x, e.expiresAt - 1)
  invalid(e, x, 'COVERAGE_FRESHNESS_INVALID', e.expiresAt)
})
for (const side of ['e', 'x']) test(`open enrollment on ${side} rejects`, () => {
  const f = fixture(); f[side as 'e' | 'x'].closedEnrollment = false
  invalid(f.e, f.x, 'COVERAGE_ENROLLMENT_OPEN')
})
for (const key of ['oldGenerationAdmissions', 'unknownNativeEffects']) {
  for (const value of [1, null, true, '0']) test(`${key} ${String(value)} is not a measured zero`, () => {
    const { e, x } = fixture(); e[key] = value; invalid(e, x, 'COVERAGE_UNRESOLVED')
  })
  test(`trusted ${key} remains unresolved even if candidate says zero`, () => {
    const { e, x } = fixture(); x[key] = 1; invalid(e, x, 'COVERAGE_UNRESOLVED')
  })
}
for (const value of [null, {}, { disposition: 'UNKNOWN', fenceRef: 'real-current-fence' },
  { disposition: 'DRAINED', fenceRef: 'old-fence' }]) {
  test(`zero counts without exact real old-generation fence disposition ${JSON.stringify(value)}`, () => {
    const { e, x } = fixture(); x.oldGenerationFence = value; invalid(e, x, 'COVERAGE_FENCE_UNPROVEN')
  })
}
test('trusted measured FENCED disposition is supported as well as DRAINED', () => {
  const { e, x } = fixture(); x.oldGenerationFence.disposition = 'FENCED'; valid(e, x)
})

// Full runtime membership, not a count of seven role labels.
test('seven labels cannot conceal an eighth authoritative instance', () => {
  const { e, x } = fixture(8); e.members.pop(); invalid(e, x, 'COVERAGE_MEMBERSHIP_MISMATCH')
})
test('extra instance rejects even if its role is known and all other members match', () => {
  const { e, x } = fixture(); e.members.push(member(7)); invalid(e, x, 'COVERAGE_MEMBERSHIP_MISMATCH')
})
test('duplicate instance cannot stand for two registrations', () => {
  const { e, x } = fixture(8); e.members[7].instanceId = e.members[0].instanceId
  invalid(e, x, 'COVERAGE_MEMBERSHIP_MISMATCH')
})
test('a missing code role fails even if a caller supplies matching invented digest', () => {
  const { e } = fixture(); e.members[2].entryId = 'generic-direct'
  invalid(e, expectation(e), 'COVERAGE_CODE_ROLE_MISSING')
})
test('unclassified member is not silently ignored', () => {
  const { e } = fixture(); e.members[2].entryId = 'unregistered-side-door'
  invalid(e, expectation(e), 'COVERAGE_MEMBER_INVALID')
})
test('empty membership does not establish a closed world', () => {
  const { e, x } = fixture(); e.members = []; invalid(e, x, 'COVERAGE_MEMBERSHIP_MISMATCH')
})
test('65th instance exceeds the bounded contract', () => {
  const { e, x } = fixture(64); e.members.push(member(64)); invalid(e, x)
})
test('trusted registration digest must actually describe its own exact instance set', () => {
  const { e, x } = fixture(); e.registrationSetDigest = x.registrationSetDigest = 'f'.repeat(64)
  invalid(e, x, 'COVERAGE_MEMBERSHIP_MISMATCH')
})
for (const field of ['launchAuthorityId', 'admissionReceiptId', 'entryDefinitionDigest', 'effectFenceRevision']) {
  test(`member ${field} drift invalidates same-generation proof`, () => {
    const { e, x } = fixture(); e.members[0][field] = field === 'effectFenceRevision' ? 3 :
      field === 'entryDefinitionDigest' ? 'f'.repeat(64) : 'another-receipt'
    invalid(e, x, 'COVERAGE_MEMBER_BINDING_MISMATCH')
  })
}
for (const field of ['releaseGeneration', 'guardSourceIdentity']) test(`member ${field} bound to current root`, () => {
  const { e, x } = fixture(); e.members[0][field] = field === 'guardSourceIdentity' ? 'f'.repeat(64) : 'old-generation'
  invalid(e, x, 'COVERAGE_MEMBER_INVALID')
})
for (const state of ['RETIRED_FENCED', 'NATIVE_NAMESPACE_DENIED']) {
  test(`lawfully ${state} optional legacy member uses exact owner receipt without restarting`, () => {
    const { e } = fixture(); e.members[2].state = state; e.members[2].admissionReceiptId = 'actual-disposition-receipt'
    valid(e, expectation(e))
  })
  test(`${state} cannot disable a mandatory guarded role`, () => {
    const { e } = fixture(); e.members[0].state = state; invalid(e, expectation(e), 'COVERAGE_REQUIRED_GUARD_MISSING')
  })
  test(`${state} without actual disposition receipt is rejected`, () => {
    const { e } = fixture(); e.members[2].state = state; e.members[2].admissionReceiptId = ''
    invalid(e, expectation(e), 'COVERAGE_MEMBER_INVALID')
  })
  test(`candidate cannot declare itself ${state} against a guarded registration`, () => {
    const { e, x } = fixture(); e.members[2].state = state; invalid(e, x, 'COVERAGE_MEMBER_BINDING_MISMATCH')
  })
}
for (const index of [0, 1, 2, 3]) test(`adjacent namespace ${adjacent[index]} needs exact exclusion coverage`, () => {
  const { e, x } = fixture(); x.namespaceExclusions.splice(index, 1)
  invalid(e, x, 'COVERAGE_NAMESPACE_UNPROVEN')
})
for (const field of ['receiptId', 'entryDefinitionDigest', 'effectFenceRevision']) test(`exclusion ${field} cannot be omitted`, () => {
  const { e, x } = fixture(); delete x.namespaceExclusions[0][field]; invalid(e, x, 'COVERAGE_NAMESPACE_UNPROVEN')
})
test('duplicate/extra/unknown adjacent namespace is not complete coverage', () => {
  const { e, x } = fixture(); x.namespaceExclusions[1] = clone(x.namespaceExclusions[0]); invalid(e, x)
  x.namespaceExclusions[1].entryId = 'unknown-neighbor'; invalid(e, x)
  x.namespaceExclusions.push(clone(x.namespaceExclusions[0])); invalid(e, x)
})

// UTF-8/generation semantics match the real Python opaque() contract.
for (const generation of ['0', '  no-trimming  ', '界'.repeat(170), '😀'.repeat(128)]) {
  test(`exact opaque generation accepted at UTF-8 budget ${Buffer.byteLength(generation)}`, () => {
    const { e } = fixture(); e.releaseGeneration = generation
    for (const m of e.members) m.releaseGeneration = generation
    valid(e, expectation(e))
  })
}
for (const generation of ['', 0, true, '界'.repeat(171), '😀'.repeat(129), '\ud800', '\udc00',
  'one\u0000two', 'one\n', 'x\u007f', 'x\u0085', 'x\u009f']) {
  test(`invalid generation shape ${JSON.stringify(generation).slice(0, 60)}`, () => {
    const { e } = fixture(); e.releaseGeneration = generation
    for (const m of e.members) m.releaseGeneration = generation
    invalid(e, expectation(e))
  })
}
test('Unicode registration hash uses Python code-point ordering, not UTF-16 sort', () => {
  const { e } = fixture(); e.members[0].instanceId = '\ue000'; e.members[1].instanceId = '\u{10000}'
  // Independently computed with Python hashlib/json.dumps(sorted(ids), ensure_ascii=False,
  // separators=(',', ':')), matching the real producer's digest implementation.
  e.registrationSetDigest = 'f5f592fd66511213b5ab6ced6ce34717f9696adc950e4b6f20d56df5be4be25c'
  valid(e, expectation(e))
  e.registrationSetDigest = sha(e.members.map((m: Input) => m.instanceId).sort())
  invalid(e, expectation(e), 'COVERAGE_MEMBERSHIP_MISMATCH')
})

function withProofBytes(target: number): { e: Input; x: Input } {
  const { e } = fixture(64)
  let missing = target - Buffer.byteLength(JSON.stringify(e))
  for (const m of e.members) for (const k of ['launchAuthorityId', 'admissionReceiptId']) {
    const add = Math.min(missing, 512 - m[k].length)
    m[k] += 'x'.repeat(add); missing -= add
  }
  assert.equal(missing, 0); assert.equal(Buffer.byteLength(JSON.stringify(e)), target)
  return { e, x: expectation(e) }
}
test('exact 65536-byte proof is accepted when every field and instance is valid', () => {
  const { e, x } = withProofBytes(CONSUMER_GUARD_MAX_BYTES); valid(e, x)
})
test('65537-byte proof fails instead of passing a character-count check', () => {
  const { e, x } = withProofBytes(CONSUMER_GUARD_MAX_BYTES + 1); invalid(e, x, 'COVERAGE_PROOF_LIMIT')
})
for (const position of ['top', 'member', 'expectation', 'exclusion', 'fence']) test(`extra ${position} fields fail closed`, () => {
  const { e, x } = fixture()
  const target = { top: e, member: e.members[0], expectation: x, exclusion: x.namespaceExclusions[0], fence: x.oldGenerationFence }[position]!
  target.secret = 'never-echo-this'; invalid(e, x)
})
for (const input of [null, true, 0, 'JSON is not a decoded observation', [], new Date(), () => true, 1n]) {
  test(`non-data proof ${typeof input} rejected`, () => { const { x } = fixture(); invalid(input, x) })
}
test('getters and toJSON are not invoked', () => {
  const { e, x } = fixture(); let calls = 0
  Object.defineProperty(e, 'issuerId', { enumerable: true, get() { calls++; throw Error('private') } })
  invalid(e, x); assert.equal(calls, 0)
  const f = fixture(); f.e.toJSON = () => { calls++; throw Error('private') }; invalid(f.e, f.x); assert.equal(calls, 0)
})
test('nested getters, proxies and revoked proxies are rejected without executing traps', () => {
  const { e, x } = fixture(); let calls = 0
  const p = new Proxy(e.members[0], { ownKeys() { calls++; throw Error('private') }, getPrototypeOf() { calls++; throw Error('private') } })
  e.members[0] = p; invalid(e, x); assert.equal(calls, 0)
  const rev = Proxy.revocable({}, {}); rev.revoke(); invalid(rev.proxy, x)
})
test('sparse arrays, array own properties, symbols and hidden fields reject', () => {
  for (const mutate of [
    (e: Input) => { delete e.members[2] },
    (e: Input) => { e.members.extra = 1 },
    (e: Input) => { e[Symbol('hidden') as any] = 1 },
    (e: Input) => { Object.defineProperty(e, 'hidden', { value: 1 }) },
  ]) { const { e, x } = fixture(); mutate(e); invalid(e, x) }
})
test('cycles, excessive nesting and forged prototypes reject with finite results', () => {
  const { e, x } = fixture(); e.members[0].instanceId = e; invalid(e, x)
  const f = fixture(); Object.setPrototypeOf(f.e, { fake: true }); invalid(f.e, f.x)
  let chain: any = {}; for (let i = 0; i < 20; i++) chain = { next: chain }; invalid(chain, x)
})
test('failures never echo raw evidence or arbitrary exception text', () => {
  const { e, x } = fixture(); e.issuerId = 'SENSITIVE_SENTINEL_NOT_A_LOG'
  const result = validate(e, x, NOW)
  assert.ok(!JSON.stringify(result).includes('SENSITIVE'))
  assert.throws(() => assertConsumerGuards(e, x, NOW), /^ConsumerGuardValidationError: COVERAGE_CONTEXT_MISMATCH$/)
})

// Compile-time readonly integration shape; not a production authority object.
const checkReadonlyType = (_expected: ConsumerGuardExpectation): void => {}
void checkReadonlyType
