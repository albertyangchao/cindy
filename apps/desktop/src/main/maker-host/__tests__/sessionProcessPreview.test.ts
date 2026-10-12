import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const state = vi.hoisted(() => ({ packaged: false }));
vi.mock('electron', () => ({ app: { get isPackaged() { return state.packaged; } } }));
const saved = { descriptor: process.env.XDT_SESSION_PROCESS_PREVIEW, isolated: process.env.XDT_ISOLATED };
let directory: string;
let spec: { workingDirectory: string; runtimeDirectory: string; seatbeltProfile: string; evidenceFile: string; expectedModel: string };
beforeEach(() => {
  vi.resetModules(); state.packaged = false;
  directory = mkdtempSync(path.join(os.tmpdir(), 'sol-preview-unit-'));
  spec = { workingDirectory: path.join(directory, 'candidate'), runtimeDirectory: path.join(directory, 'runtime'),
    seatbeltProfile: '(version 1)\n(allow default)', evidenceFile: path.join(directory, 'projection.jsonl'), expectedModel: 'gpt-6.1-sol' };
  process.env.XDT_ISOLATED = '1'; process.env.XDT_SESSION_PROCESS_PREVIEW = path.join(directory, 'descriptor.json');
  writeFileSync(process.env.XDT_SESSION_PROCESS_PREVIEW, JSON.stringify(spec));
});
afterEach(() => {
  for (const [key, value] of Object.entries({ XDT_SESSION_PROCESS_PREVIEW: saved.descriptor, XDT_ISOLATED: saved.isolated })) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
});
describe('trusted isolated development process binding', () => {
  it('keeps ordinary sessions unchanged when not enabled', async () => {
    delete process.env.XDT_SESSION_PROCESS_PREVIEW;
    const { resolveSessionProcessPreview } = await import('../session-process-preview');
    expect(await resolveSessionProcessPreview({ kind: 'codex', workingDirectory: '/ordinary' })).toBeUndefined();
  });
  it.each(['packaged', 'not-isolated'])('refuses %s even with a descriptor', async mode => {
    state.packaged = mode === 'packaged'; if (mode === 'not-isolated') delete process.env.XDT_ISOLATED;
    const { resolveSessionProcessPreview } = await import('../session-process-preview');
    await expect(resolveSessionProcessPreview({ kind: 'codex', workingDirectory: spec.workingDirectory })).rejects.toThrow('REQUIRES_ISOLATED');
  });
  it('refuses workspace mismatch and absent bridge metadata', async () => {
    const { resolveSessionProcessPreview } = await import('../session-process-preview');
    await expect(resolveSessionProcessPreview({ kind: 'codex', workingDirectory: '/wrong' })).rejects.toThrow('WORKSPACE_MISMATCH');
    await expect(resolveSessionProcessPreview({ kind: 'codex', workingDirectory: spec.workingDirectory })).rejects.toThrow('METADATA_MISSING');
  });
  it.each(['https://127.0.0.1:1234', 'http://remote.invalid:1234', 'http://127.0.0.1', 'http://user:password@127.0.0.1:1234'])('refuses non-host-owned endpoint %s', async endpoint => {
    const { resolveSessionProcessPreview } = await import('../session-process-preview');
    await expect(resolveSessionProcessPreview({ kind: 'codex', workingDirectory: spec.workingDirectory, networkEndpoints: [endpoint] })).rejects.toThrow();
  });
  it('binds only the actual existing loopback bridge ports, preserving filesystem policy', async () => {
    const { resolveSessionProcessPreview } = await import('../session-process-preview');
    const isolation = await resolveSessionProcessPreview({ kind: 'codex', workingDirectory: spec.workingDirectory,
      networkEndpoints: ['http://127.0.0.1:12345/v1', 'http://127.0.0.1:12345/responses'] });
    expect(isolation?.seatbeltProfile).toBe(spec.seatbeltProfile + '\n(deny network-outbound (require-all (require-not (remote ip "localhost:12345"))))');
  });
  it('projects only final model/effort/tier; never reads prompt or credential getters', async () => {
    const { recordSessionPreviewModelParameters } = await import('../session-process-preview');
    const payload = { model: 'gpt-6.1-sol', reasoning: { effort: 'high' }, service_tier: 'default',
      get headers() { throw new Error('must not read headers'); }, get input() { throw new Error('must not read input'); } };
    recordSessionPreviewModelParameters(payload);
    const recorded = JSON.parse(readFileSync(spec.evidenceFile, 'utf8'));
    expect(recorded).toMatchObject({ model: 'gpt-6.1-sol', effort: 'high', serviceTier: 'default', responseModel: 'UNKNOWN' });
    expect(Object.keys(recorded).sort()).toEqual(['effort', 'evidenceKind', 'model', 'responseModel', 'serviceTier', 'timestamp']);
  });
  it('does not substitute configuration for a missing request', async () => {
    const { recordSessionPreviewModelParameters } = await import('../session-process-preview');
    recordSessionPreviewModelParameters(Buffer.from(JSON.stringify({ model: 'other', reasoning: {}, service_tier: 'untrusted' })));
    expect(JSON.parse(readFileSync(spec.evidenceFile, 'utf8'))).toMatchObject({ model: 'UNKNOWN', effort: 'UNKNOWN', serviceTier: 'UNKNOWN' });
  });
});
