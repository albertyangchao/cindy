import { expect, it, vi } from 'vitest';
import * as fs from 'node:fs/promises';
import { dirname } from 'node:path';
import sharp from 'sharp';
const command = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({
  execFile: Object.assign(() => {}, { [Symbol.for('nodejs.util.promisify.custom')]: command }),
}));
import { normalizeRestrictedUrlImage } from '../../maker-ipc/restrictedPartnerUrlInput.js';
import { sniffRestrictedInputImage } from '../restrictedMediaImage.js';

function heic() {
  const bytes = Buffer.alloc(24);
  bytes.writeUInt32BE(24); bytes.write('ftyp', 4); bytes.write('isom', 8);
  bytes.write('heic', 16); bytes.write('mif1', 20);
  return bytes;
}

/* W0 regression: inbound URL MIME sniff refused HEIC before normalization; a MIME
 * enum alone would still not decode it on shipped AVIF-only sharp builds.
 * The fixed native-command port is synthetic; real PNG bytes and filesystem
 * cleanup/limits are tested through the production URL normalizer. Actual macOS
 * ImageIO decoding remains a local acceptance check. Tier: focused media unit. */
it('URL HEIC uses the fixed decoder with private bounded files and returns metadata-free PNG', async () => {
  const input = heic();
  const png = await sharp({ create: { width: 3, height: 2, channels: 3, background: '#345678' } })
    .png().withMetadata().toBuffer();
  let scratch = '';
  command.mockImplementation(async (file: string, args: string[], options: any) => {
    expect(file).toBe('/usr/bin/sips'); expect(options.timeout).toBe(5000); expect(options.maxBuffer).toBe(65536);
    const source = args[0] === '-g' ? args[4] : args[3]; scratch = dirname(source);
    expect(await fs.readFile(source)).toEqual(input);
    expect((await fs.stat(source)).mode & 0o777).toBe(0o600);
    if (args[0] === '-g') return { stdout: 'pixelWidth: 3\npixelHeight: 2\n', stderr: '' };
    expect(args.slice(0, 3)).toEqual(['-s', 'format', 'png']);
    expect(args[4]).toBe('--out'); await fs.writeFile(args[5], png);
    return { stdout: '', stderr: '' };
  });
  let checks = 0;
  expect(sniffRestrictedInputImage(input)).toBe('image/heic');
  const output = await normalizeRestrictedUrlImage(input, 'image/heic', () => { checks++; });
  const metadata = await sharp(output).metadata();
  expect(metadata.format).toBe('png'); expect(metadata.width).toBe(3); expect(metadata.height).toBe(2);
  expect(metadata.exif).toBeUndefined(); expect(checks).toBeGreaterThan(8);
  expect(command).toHaveBeenCalledTimes(2); await expect(fs.stat(scratch)).rejects.toMatchObject({ code: 'ENOENT' });
});

it('decoder refuses MIME spoofing, conflicting brands, excess pixels, lost authority and missing local capability', async () => {
  const input = heic(); command.mockClear();
  await expect(normalizeRestrictedUrlImage(input, 'image/png', () => {})).rejects.toThrow('DENIED');
  const conflict = Buffer.from(input); conflict.write('avif', 20);
  await expect(normalizeRestrictedUrlImage(conflict, 'image/heic', () => {})).rejects.toThrow('DENIED');
  expect(command).not.toHaveBeenCalled();
  let scratch = '';
  command.mockImplementation(async (_file: string, args: string[]) => {
    scratch = dirname(args[4]);
    return { stdout: 'pixelWidth: 20000\npixelHeight: 20000\n', stderr: '' };
  });
  await expect(normalizeRestrictedUrlImage(input, 'image/heic', () => {})).rejects.toThrow('DENIED');
  expect(command).toHaveBeenCalledTimes(1); await expect(fs.stat(scratch)).rejects.toMatchObject({ code: 'ENOENT' });
  command.mockClear(); let live = true;
  command.mockImplementation(async (_file: string, args: string[]) => {
    scratch = dirname(args[4]); live = false;
    return { stdout: 'pixelWidth: 3\npixelHeight: 2\n', stderr: '' };
  });
  await expect(normalizeRestrictedUrlImage(input, 'image/heic', () => { if (!live) throw Error('REVOKED'); })).rejects.toThrow('REVOKED');
  expect(command).toHaveBeenCalledTimes(1); await expect(fs.stat(scratch)).rejects.toMatchObject({ code: 'ENOENT' });
  command.mockImplementation(async () => { throw Object.assign(Error('private diagnostic'), { code: 'ENOENT' }); });
  await expect(normalizeRestrictedUrlImage(input, 'image/heic', () => {})).rejects.toThrow('HEIC_DECODER_MISSING');
});
