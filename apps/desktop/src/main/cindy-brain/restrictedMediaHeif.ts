import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import sharp from 'sharp';
import { isRestrictedHeif, sniffRestrictedInputImage } from './restrictedMediaImage.js';

const execute = promisify(execFile);
const deny = (): never => { throw Error('RESTRICTED_PARTNER_URL_IMAGE_DENIED'); };

/** Fixed local macOS ImageIO decoder. No shell, external path, URL or provider.
 * Sharp's prebuilt HEIF support can be AVIF-only; this is an actual decode route,
 * never a MIME-only declaration of HEIC support. */
export async function decodeRestrictedHeif(bytes: Uint8Array, current: () => void) {
  current();
  if (!bytes.length || bytes.length > 8 * 1024 * 1024 ||
      !isRestrictedHeif(sniffRestrictedInputImage(bytes) ?? '')) deny();
  const directory = await fs.mkdtemp(join(tmpdir(), 'cindy-restricted-heif-')).catch(() => deny());
  const source = join(directory, 'input.heic');
  const target = join(directory, 'decoded.png');
  const run = async (args: string[]) => {
    current();
    try {
      const result = await execute('/usr/bin/sips', args, {
        timeout: 5000, maxBuffer: 65536, encoding: 'utf8', windowsHide: true,
      });
      current();
      return result.stdout;
    } catch (error) {
      current();
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw Error('HEIC_DECODER_MISSING');
      return deny();
    }
  };
  try {
    current();
    await fs.writeFile(source, bytes, { mode: 0o600, flag: 'wx' });
    current();
    const metadata = await run(['-g', 'pixelWidth', '-g', 'pixelHeight', source]);
    const width = Number(/pixelWidth:\s*(\d+)/.exec(metadata)?.[1]);
    const height = Number(/pixelHeight:\s*(\d+)/.exec(metadata)?.[1]);
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) ||
        width < 1 || height < 1 || width * height > 16_000_000) deny();
    await run(['-s', 'format', 'png', source, '--out', target]);
    const file = await fs.open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    let png: Buffer;
    try {
      current();
      const info = await file.stat();
      if (!info.isFile() || !info.size || info.size > 8 * 1024 * 1024) deny();
      png = await file.readFile();
      current();
    } finally {
      await file.close();
    }
    if (sniffRestrictedInputImage(png!) !== 'image/png') deny();
    const decoded = await sharp(png!, { limitInputPixels: 16_000_000, failOn: 'warning' })
      .timeout({ seconds: 5 }).metadata();
    current();
    if (decoded.width !== width || decoded.height !== height || (decoded.pages ?? 1) !== 1) deny();
    return png!;
  } catch (error) {
    current();
    if ((error as Error).message === 'HEIC_DECODER_MISSING') throw error;
    return deny();
  } finally {
    await fs.rm(directory, { recursive: true, force: true }).catch(() => {});
  }
}
