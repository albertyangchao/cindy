import { sniffMediaMime } from '../cindy-media/sniffMediaMime.js';

/** Input-only formats. Original HEIF bytes never enter the managed blob store;
 * the trusted decoder must produce a bounded PNG before existing ingestMedia. */
export function sniffRestrictedInputImage(bytes: Uint8Array): string | null {
  if (!(bytes instanceof Uint8Array) || !bytes.length) return null;
  const ascii = (start: number, end: number) =>
    String.fromCharCode(...bytes.subarray(start, end));
  if (ascii(4, 8) === 'ftyp') {
    if (bytes.length < 16) return null;
    const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
    if (size < 16 || size > Math.min(bytes.length, 4096) || size % 4) return null;
    const brands = new Set([ascii(8, 12)]);
    for (let offset = 16; offset < size; offset += 4) brands.add(ascii(offset, offset + 4));
    const avif = ['avif', 'avis'].some((brand) => brands.has(brand));
    const heic = ['heic', 'heix', 'hevc', 'hevx'].some((brand) => brands.has(brand));
    if (avif && heic) return null;
    if (avif) return 'image/avif';
    if (heic) return 'image/heic';
    if (['heif', 'mif1', 'msf1'].some((brand) => brands.has(brand))) return 'image/heif';
    return null;
  }
  if (ascii(0, 2) === 'BM') return 'image/bmp';
  if (['II*\0', 'MM\0*'].includes(ascii(0, 4))) return 'image/tiff';
  const mime = sniffMediaMime(bytes);
  return mime?.startsWith('image/') ? mime : null;
}

export const isRestrictedHeif = (mime: string) => mime === 'image/heic' || mime === 'image/heif';
