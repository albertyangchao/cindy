/** Test value: the production wire projection must commit every current and
 * historical row, independent of locale/insertion order, and never accept an
 * over-cap or unretired history. Existing resident tests cover private handles;
 * this unit file tests serialization only and makes no original-owner claim.
 * Minimal regression inputs are one retained old row and two non-ASCII IDs.
 */
import { expect, it } from 'vitest';
import { digest } from '../restrictedPublicationProtocol.js';
import { publicationCensusCommitment, publicationReceiptSet } from '../restrictedPublicationOwnerRegistry.js';

const source = { sourceId: 'resident', authorityId: 'original-authority', kind: 'resident' as const };
const record = (instanceId: string, generation = 'current') => ({ instanceId, generation,
  entryId: 'canonical-producer', definitionDigest: digest(instanceId), state: 'RETIRED_FENCED' as const,
  serviceLabel: `service.${instanceId}` });
const exclusion = (serviceLabel: string) => ({ serviceLabel, definitionDigest: digest(serviceLabel),
  sourceProfileId: 'monitor-source', censusSourceId: source.sourceId });
const commit = (records: ReturnType<typeof record>[], nonPublishers: ReturnType<typeof exclusion>[] = []) =>
  publicationCensusCommitment(source, 'sealed-snapshot', 7, 'current', records, nonPublishers);

it('commits the complete retained current and historical sets with separate counts', () => {
  const records = [record('current-owner'), record('old-owner', 'old')];
  const exclusions = [exclusion('service.z'), exclusion('service.a')];
  const value = commit(records, exclusions);
  expect(value).toMatchObject({ currentRecordCount: 1, historicalRecordCount: 1, nonPublisherCount: 2,
    sourceId: source.sourceId, authorityId: source.authorityId, snapshotId: 'sealed-snapshot', revision: 7 });
  expect(value.recordsSha256).toBe(digest(records));
  expect(value.nonPublishersSha256).toBe(digest([...exclusions].reverse()));
  expect(commit(records.slice(0, 1), exclusions).recordsSha256).not.toBe(value.recordsSha256);
});

it('uses explicit UTF-8 order for both collections without mutating the acquired arrays', () => {
  const records = [record('𐀀'), record('\uE000'), record('z'), record('a')];
  const exclusions = [exclusion('service.z'), exclusion('service.a')];
  const before = structuredClone({ records, exclusions });
  const ordered = [records[3], records[2], records[1], records[0]];
  const value = commit(records, exclusions);
  expect(value.recordsSha256).toBe(digest(ordered));
  expect(commit([...records].reverse(), [...exclusions].reverse())).toEqual(value);
  expect({ records, exclusions }).toEqual(before);
});

it('retains the 64-member bound without truncating the oldest record', () => {
  const records = Array.from({ length: 64 }, (_, i) => record(`owner-${i}`, 'old'));
  expect(commit(records).historicalRecordCount).toBe(64);
  expect(() => commit([...records, record('owner-64', 'old')])).toThrow('CENSUS_COMMITMENT');
});

it('rejects duplicated members, duplicated exclusions and unretired historical rows', () => {
  expect(() => commit([record('same'), record('same')])).toThrow('CENSUS_COMMITMENT');
  expect(() => commit([], [exclusion('same'), exclusion('same')])).toThrow('CENSUS_COMMITMENT');
  expect(() => publicationCensusCommitment(source, 'snapshot', 1, 'current',
    [{ ...record('old', 'old'), state: 'GUARDED' }], [])).toThrow('CENSUS_COMMITMENT');
});

it('keeps nonpublisher descriptors in their actual resident source', () => {
  expect(() => commit([], [{ ...exclusion('service.a'), censusSourceId: 'different' }])).toThrow('CENSUS_COMMITMENT');
  expect(() => publicationCensusCommitment({ ...source, kind: 'managed' }, 'snapshot', 1,
    'current', [], [exclusion('service.a')])).toThrow('CENSUS_COMMITMENT');
});

it('commits every acquired receipt with an order-independent count and root', () => {
  const ids = Array.from({ length: 2048 }, (_, i) => digest(i));
  const value = publicationReceiptSet(ids);
  expect(value.count).toBe(ids.length);
  expect(publicationReceiptSet([...ids].reverse())).toEqual(value);
  expect(publicationReceiptSet(ids.slice(1)).sha256).not.toBe(value.sha256);
  expect(() => publicationReceiptSet([...ids, ids[0]])).toThrow('RECEIPT_SET');
});
