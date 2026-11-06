/** Main-only inbound image source validation. A model URL is never an input asset. */
import { createHash } from 'node:crypto';
import sharp from 'sharp';
import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';
import type { MediaBinding } from '../cindy-brain/restrictedMediaAdapter.js';
import type {
  RestrictedPartnerGrant,
  RestrictedPartnerClaim,
  RestrictedInputAsset,
} from './restrictedPartnerExecution.js';
import { grantResourceFingerprint } from './restrictedPartnerRequirements.js';
const sha = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const deny = (): never => {
  throw Error('RESTRICTED_PARTNER_URL_INPUT_DENIED');
};
export interface RestrictedUrlInputAsset {
  type: 'image-url';
  id: string;
  url: string;
  urlSha256: string;
  questionSha256: string;
  addressHash: string;
  binding: MediaBinding;
}
export function originalImageUrls(question: string): string[] {
  const values = [...new Set(question.match(/https?:\/\/[^\s<>"']+/gi) ?? [])];
  if (values.length > 2) deny();
  for (const raw of values) {
    if (raw.length > 8192) deny();
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      deny();
    }
    if (
      u!.protocol !== 'https:' ||
      u!.username ||
      u!.password ||
      u!.hash ||
      u!.hostname.endsWith('.') ||
      !u!.hostname.includes('.') ||
      /[\[\]:]/.test(u!.hostname) ||
      /^\d+(\.\d+){3}$/.test(u!.hostname) ||
      (u!.port && u!.port !== '443') ||
      u!.href !== raw
    )
      deny();
  }
  return values;
}
function questionEnvelope(text: string): {
  question: string;
  facts: unknown[];
  documents: unknown[];
} {
  let p;
  try {
    p = JSON.parse(text);
  } catch {
    deny();
  }
  if (
    !p ||
    Array.isArray(p) ||
    Object.keys(p).some((k) => !['question', 'facts', 'documents'].includes(k)) ||
    typeof p.question !== 'string' ||
    !Array.isArray(p.facts) ||
    !Array.isArray(p.documents)
  )
    deny();
  return p;
}
export function validateRestrictedUrlInput(
  g: RestrictedPartnerGrant,
  claim: Pick<RestrictedPartnerClaim, 'inputId' | 'inputText' | 'channel'>,
  a: RestrictedUrlInputAsset,
) {
  if (
    !a ||
    Object.keys(a).sort().join(',') !==
      'addressHash,binding,id,questionSha256,type,url,urlSha256' ||
    a.type !== 'image-url' ||
    typeof a.url !== 'string' ||
    a.url.length > 8192 ||
    typeof a.id !== 'string' ||
    !/^url:[a-f0-9]{64}$/.test(a.id) ||
    [a.urlSha256, a.questionSha256, a.addressHash].some(
      (x) => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x),
    )
  )
    deny();
  const c = claim.channel,
    route = g.media?.vision ?? g.media?.edit;
  if (
    !c ||
    !route ||
    !c.addressHash ||
    g.dispatchEnabled !== true ||
    sha(JSON.stringify([c.domainId, c.principalId])) !== g.principalId ||
    !g.requirements?.addressHashes.includes(c.addressHash) ||
    a.addressHash !== c.addressHash ||
    !g.requirements.addressHashes.includes(a.addressHash) ||
    !claim.inputText
  )
    deny();
  const question = questionEnvelope(claim.inputText!).question;
  if (
    a.questionSha256 !== sha(question) ||
    a.urlSha256 !== sha(a.url) ||
    !originalImageUrls(question).includes(a.url)
  )
    deny();
  const expected: MediaBinding = {
    domainId: c!.domainId,
    connectionId: c!.connectionId,
    generation: c!.generation,
    chatId: c!.chatId,
    eventId: c!.eventId,
    revision: c!.revision,
    epoch: g.dispatchEpoch,
    principalId: g.principalId,
    partnerId: g.partnerId,
    runId: 'input:' + claim.inputId,
    resourceFingerprint: grantResourceFingerprint(g),
    providerId: route!.providerId,
    modelId: route!.modelId,
    effectSlot: 'input-url:' + a.urlSha256,
  };
  if (
    !a.binding ||
    Object.keys(a.binding).length !== Object.keys(expected).length ||
    Object.entries(expected).some(([k, v]) => a.binding[k as keyof MediaBinding] !== v) ||
    c!.epoch !== g.dispatchEpoch ||
    a.id !==
      'url:' +
        sha(
          JSON.stringify([
            Object.entries(expected).sort(([a], [b]) => a.localeCompare(b)),
            a.addressHash,
            a.questionSha256,
            a.urlSha256,
          ]),
        )
  )
    deny();
  return expected;
}
/** Persisted original claim is kept unchanged; only the runner/history projection is redacted. */
export function projectedUrlInput(
  g: RestrictedPartnerGrant,
  claim: Pick<RestrictedPartnerClaim, 'inputId' | 'inputText' | 'channel'>,
  assets: RestrictedInputAsset[],
) {
  const urls = assets.filter((a): a is RestrictedUrlInputAsset => a.type === 'image-url');
  if (!urls.length) {
    if (claim.inputText) {
      let question = claim.inputText;
      try {
        question = JSON.parse(question)?.question ?? question;
      } catch {}
      if (typeof question === 'string' && /https?:\/\//i.test(question)) deny();
    }
    return claim.inputText;
  }
  if (urls.length > 2 || new Set(urls.map((a) => a.urlSha256)).size !== urls.length) deny();
  const p = questionEnvelope(claim.inputText!);
  const original = originalImageUrls(p.question);
  if (original.length !== urls.length) deny();
  for (const a of urls) {
    validateRestrictedUrlInput(g, claim, a);
    p.question = p.question.split(a.url).join('[approved image source ' + a.id + '; URL withheld]');
  }
  // Do not let an injected fact/document smuggle the same source URL into model context.
  let result = JSON.stringify(p);
  for (const a of urls) result = result.split(a.url).join('[image URL withheld]');
  return result;
}
export function withoutRawImageUrls(text: string): string {
  return text.replace(
    /https?:\/\/[^\s<>"']+/gi,
    '[image URL withheld; use authorized managed asset]',
  );
}
export async function normalizeRestrictedUrlImage(
  bytes: Uint8Array,
  mimeType: string,
  current: () => void,
) {
  current();
  if (
    !bytes.length ||
    bytes.length > 8 * 1024 * 1024 ||
    !['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(mimeType) ||
    sniffMediaMime(bytes) !== mimeType
  )
    deny();
  try {
    const image = sharp(Buffer.from(bytes), {
      limitInputPixels: 16_000_000,
      failOn: 'warning',
      animated: false,
    }).timeout({ seconds: 5 });
    const info = await image.metadata();
    current();
    if (
      !info.width ||
      !info.height ||
      info.width * info.height > 16_000_000 ||
      (info.pages ?? 1) !== 1
    )
      deny();
    const normalized = await image
      .rotate()
      .resize({ width: 2048, height: 2048, fit: 'inside', withoutEnlargement: true })
      .png({ compressionLevel: 9 })
      .toBuffer();
    current();
    if (
      !normalized.length ||
      normalized.length > 4 * 1024 * 1024 ||
      sniffMediaMime(normalized) !== 'image/png'
    )
      deny();
    return normalized;
  } catch {
    throw Error('RESTRICTED_PARTNER_URL_IMAGE_DENIED');
  }
}
