import { expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import sharp from 'sharp';
import { nativeImageUrlAuthority } from '../restrictedPartnerUrlApproval.js';
import {
  normalizeRestrictedUrlImage,
  originalImageUrls,
  selectedImageUrls,
  validateRestrictedUrlInput,
  projectedUrlInput,
} from '../restrictedPartnerUrlInput.js';
import { grantResourceFingerprint } from '../restrictedPartnerRequirements.js';
const sha = (v: string | Uint8Array) => createHash('sha256').update(v).digest('hex');
/* W0 contract regression: the producer used every URL as an image and Main
 * rejected harmless references. Shared vectors cover exact source selection;
 * projection checks prove ordinary links are not fetch/model capabilities.
 * Tier: existing focused URL input tests, no network or real approvals. */
it('shared mixed-link vectors select only explicit original images and redact ordinary references', () => {
  const vectors = JSON.parse(readFileSync(new URL('./fixtures/restricted-image-url-cases.json', import.meta.url), 'utf8'));
  for (const value of vectors) {
    if (value.denied) expect(() => selectedImageUrls(value.question)).toThrow('DENIED');
    else expect(selectedImageUrls(value.question)).toEqual(value.selected);
  }
  const { g, claim } = source();
  claim.inputText = JSON.stringify({question:'Read http://docs.example.invalid/reference',facts:['https://notes.example.invalid/private'],documents:[]});
  const projected = projectedUrlInput(g, claim, [])!;
  expect(projected).toContain('Read');
  expect(projected).not.toMatch(/https?:\/\//i);
  expect(claim.inputText).toContain('http://docs.example.invalid/reference');
  const mixed = source();
  const question = 'Reference https://docs.example.invalid/reference and describe image ' + mixed.a.url;
  mixed.claim.inputText = JSON.stringify({ question, facts: ['https://notes.example.invalid/private'], documents: [] });
  mixed.a.questionSha256 = sha(question);
  mixed.a.id = 'url:' + sha(JSON.stringify([
    Object.entries(mixed.a.binding).sort(([a], [b]) => a.localeCompare(b)),
    mixed.a.addressHash, mixed.a.questionSha256, mixed.a.urlSha256,
  ]));
  const mixedProjection = projectedUrlInput(mixed.g, mixed.claim, [mixed.a])!;
  expect(mixedProjection).toContain(mixed.a.id);
  expect(mixedProjection).not.toMatch(/https?:\/\//i);
  expect(() => projectedUrlInput(mixed.g, mixed.claim, [])).toThrow('DENIED');
});
function source() {
  const url = 'https://images.example.invalid/original.png?marker=SYNTHETIC_PRIVATE';
  const principalId = sha(JSON.stringify(['domain', 'subject'])),
    addressHash = sha('synthetic-address');
  const g: any = {
    id: 'grant',
    revision: 1,
    pluginId: 'plugin',
    principalId,
    partnerId: 'synthetic-bot',
    enabled: true,
    dispatchEnabled: true,
    dispatchEpoch: 3,
    resources: [],
    resourceIds: [],
    media: { vision: { providerId: 'fake', modelId: 'vision' } },
    requirements: { addressHashes: [addressHash] },
  };
  const c = {
    domainId: 'domain',
    principalId: 'subject',
    connectionId: 'c',
    generation: 'g',
    chatId: 'original',
    eventId: 'event',
    revision: 4,
    epoch: 3,
    addressHash,
  };
  const question = 'Describe ' + url,
    claim: any = {
      inputId: sha('input'),
      inputText: JSON.stringify({ question, facts: [], documents: [] }),
      channel: c,
    };
  const binding = {
    domainId: c.domainId,
    connectionId: c.connectionId,
    generation: c.generation,
    chatId: c.chatId,
    eventId: c.eventId,
    revision: c.revision,
    epoch: 3,
    principalId,
    partnerId: g.partnerId,
    runId: 'input:' + claim.inputId,
    resourceFingerprint: grantResourceFingerprint(g),
    providerId: 'fake',
    modelId: 'vision',
    effectSlot: 'input-url:' + sha(url),
  };
  const a: any = {
    type: 'image-url',
    id:
      'url:' +
      sha(
        JSON.stringify([
          Object.entries(binding).sort(([a], [b]) => a.localeCompare(b)),
          addressHash,
          sha(question),
          sha(url),
        ]),
      ),
    url,
    urlSha256: sha(url),
    questionSha256: sha(question),
    addressHash,
    binding,
  };
  return { g, c, claim, a };
}
it('exact captured source validates while forged URL/event/principal/address/question/revision/epoch/role and extra keys refuse', () => {
  const { g, claim, a } = source();
  expect(validateRestrictedUrlInput(g, claim, a)).toEqual(a.binding);
  for (const bad of [
    { ...a, url: a.url + '/other' },
    { ...a, questionSha256: sha('other') },
    { ...a, addressHash: sha('alias') },
    { ...a, origin: 'model' },
    ...['eventId', 'chatId', 'principalId', 'revision', 'epoch', 'effectSlot'].map((k) => ({
      ...a,
      binding: { ...a.binding, [k]: k === 'revision' || k === 'epoch' ? 9 : 'other' },
    })),
  ])
    expect(() => validateRestrictedUrlInput(g, claim, bad)).toThrow('DENIED');
  expect(() =>
    validateRestrictedUrlInput({ ...g, requirements: { addressHashes: [sha('other')] } }, claim, a),
  ).toThrow('DENIED');
  expect(() => projectedUrlInput(g, claim, [])).toThrow('DENIED');
  const projected = projectedUrlInput(g, claim, [a])!;
  expect(projected).toContain(a.id);
  expect(projected).not.toContain(a.url);
  expect(projected).not.toContain('SYNTHETIC_PRIVATE');
  expect(claim.inputText).toContain(a.url);
});
it('source extraction is bounded HTTPS and rejects opaque credentials, noncanonical links and unsupported host forms', () => {
  expect(originalImageUrls('Describe https://images.example.invalid/a.png')).toEqual([
    'https://images.example.invalid/a.png',
  ]);
  for (const q of [
    'https://user:pass@images.example.invalid/a.png',
      'HTTPS://images.example.invalid/a.png', 'http://images.example.invalid/a.png',
    'https://127.0.0.1/a.png',
    'https://images.example.invalid/a.png#fragment',
    'https://images.example.invalid/a https://images.example.invalid/b https://images.example.invalid/c',
  ])
    expect(() => originalImageUrls(q)).toThrow('DENIED');
});
it('actual native approval bridge defaults cancel, separates input/output and same URL/event/subject authority; late/rebound answers cannot approve', async () => {
  const { g, a } = source();
  let active = true;
  const current = () => {
    if (!active) throw Error('REVOKED');
  };
  const window: any = { isDestroyed: () => false };
  let answer = 0;
  const show = vi.fn(async (_win: any, o: any) => {
    expect(o.defaultId).toBe(0);
    expect(o.cancelId).toBe(0);
    expect(o.detail).not.toContain(a.url);
    return { response: answer };
  });
  const native = nativeImageUrlAuthority(g, current, {
    window: () => window,
    trusted: () => true,
    show: show as any,
  });
  const p: any = {
    binding: a.binding,
    kind: 'vision',
    signal: new AbortController().signal,
    assertCurrent: current,
  };
  expect(() => native.authorize(p, a.url, 'input')).toThrow('DENIED');
  await expect(native.approve(p, a.url, 'input')).rejects.toThrow('DENIED');
  answer = 1;
  await native.approve(p, a.url, 'input');
  expect(native.authorize(p, a.url, 'input').role).toBe('input');
  expect(() => native.authorize(p, a.url, 'output')).toThrow('DENIED');
  expect(() =>
    native.authorize({ ...p, binding: { ...a.binding, eventId: 'other' } }, a.url, 'input'),
  ).toThrow('DENIED');
  expect(() =>
    native.authorize({ ...p, binding: { ...a.binding, principalId: 'other' } }, a.url, 'input'),
  ).toThrow('DENIED');
  show.mockImplementationOnce(async () => {
    active = false;
    return { response: 1 };
  });
  await expect(
    native.approve({ ...p, binding: { ...a.binding, eventId: 'late' } }, a.url, 'input'),
  ).rejects.toThrow('REVOKED');
});
it('real sharp normalization strips metadata, bounds pixels/bytes and checks live scope around await; malformed/nonimage inputs refuse', async () => {
  const bytes = await sharp({
    create: { width: 12, height: 8, channels: 3, background: '#445566' },
  })
    .jpeg()
    .withMetadata({ orientation: 6 })
    .toBuffer();
  let checks = 0;
  const normalized = await normalizeRestrictedUrlImage(bytes, 'image/jpeg', () => {
    checks++;
  });
  expect((await sharp(normalized).metadata()).format).toBe('png');
  expect(checks).toBeGreaterThanOrEqual(3);
  expect((await sharp(normalized).metadata()).exif).toBeUndefined();
  await expect(
    normalizeRestrictedUrlImage(Buffer.from('<html>not image</html>'), 'image/png', () => {}),
  ).rejects.toThrow('DENIED');
  await expect(normalizeRestrictedUrlImage(bytes, 'image/png', () => {})).rejects.toThrow('DENIED');
  await expect(
    normalizeRestrictedUrlImage(new Uint8Array(8 * 1024 * 1024 + 1), 'image/png', () => {}),
  ).rejects.toThrow('DENIED');
  await expect(
    normalizeRestrictedUrlImage(bytes, 'image/jpeg', () => {
      if (++checks > 5) throw Error('REVOKED');
    }),
  ).rejects.toThrow();
});
