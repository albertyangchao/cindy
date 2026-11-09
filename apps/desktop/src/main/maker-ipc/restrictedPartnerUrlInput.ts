/** Main-only inbound image source validation. A model URL is never an input asset. */
import { createHash } from 'node:crypto';
import sharp from 'sharp';
import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';
import { isRestrictedHeif, sniffRestrictedInputImage } from '../cindy-brain/restrictedMediaImage.js';
import { decodeRestrictedHeif } from '../cindy-brain/restrictedMediaHeif.js';
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
/** Same candidate contract as the plugin; these hints never approve a fetch. */
export function selectedImageUrls(question: string): string[] {
  const raw = [...new Set(question.match(/https?:\/\/[^\s<>"']+/gi) ?? [])];
  const prose = question.replace(/https?:\/\/[^\s<>"']+/gi, '');
  const imageIntent = /图片|图像|照片|相片|改图|图中|这张|\b(?:image|images|photo|photos|picture|pictures)\b/i.test(prose);
  const images = raw.filter((value) => {
    try {
      return /\.(?:png|jpe?g|webp|gif|heic|heif|avif|bmp|tiff?)$/i.test(new URL(value).pathname);
    } catch {
      return false;
    }
  });
  if (!images.length && imageIntent && raw.length > 1) deny();
  return originalImageUrls((images.length ? images : imageIntent ? raw : []).join(' '));
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
  // The descriptor may use either image route the owner actually approved.
  // Public capability inspection can report vision unavailable while an
  // independently approved edit route is still live. Bind to the exact route
  // in the descriptor instead of silently substituting the first grant route.
  const c = claim.channel,
    route = [g.media?.vision, g.media?.edit].find(
      (candidate) => candidate &&
        candidate.providerId === a.binding?.providerId &&
        candidate.modelId === a.binding?.modelId,
    );
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
    !selectedImageUrls(question).includes(a.url)
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
  if (!urls.length && (!claim.inputText || !/https?:\/\//i.test(claim.inputText))) return claim.inputText;
  if (urls.length > 2 || new Set(urls.map((a) => a.urlSha256)).size !== urls.length) deny();
  const p = questionEnvelope(claim.inputText!);
  const original = selectedImageUrls(p.question);
  if (original.length !== urls.length) deny();
  for (const a of urls) {
    validateRestrictedUrlInput(g, claim, a);
    p.question = p.question.split(a.url).join('[approved image source ' + a.id + '; URL withheld]');
  }
  // Ordinary page references never become input assets or fetch authority. All
  // raw links, including injected fact/document links, are withheld from runner
  // and history while the durable original claim remains unchanged.
  return withoutRawImageUrls(JSON.stringify(p));
}
export function withoutRawImageUrls(text: string): string {
  return text.replace(
    /https?:\/\/[^\s<>"']+/gi,
    '[reference URL withheld; this reference does not authorize a download]',
  );
}
export async function normalizeRestrictedUrlImage(
  bytes: Uint8Array,
  mimeType: string,
  current: () => void,
): Promise<Buffer> {
  current();
  if (
    !bytes.length ||
    bytes.length > 8 * 1024 * 1024 ||
    !['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/heic', 'image/heif',
      'image/avif', 'image/bmp', 'image/tiff'].includes(mimeType) ||
    sniffRestrictedInputImage(bytes) !== mimeType
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
    current();
    if (isRestrictedHeif(mimeType)) {
      const decoded = await decodeRestrictedHeif(bytes, current);
      current();
      return normalizeRestrictedUrlImage(decoded, 'image/png', current);
    }
    throw Error('RESTRICTED_PARTNER_URL_IMAGE_DENIED');
  }
}
