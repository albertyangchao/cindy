import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resolveOwnerPublicationRoot } from '../ownerPublicationRoot.js';

/** Test value: Main's new D2 source selector must not turn absent configuration,
 * mutable checkout files or an import shadow into owner publication authority.
 * Existing controlled-publication fixtures never resolve this additive source.
 * Minimal failure inputs are one dirty producer byte, an added module or changed
 * environment. Unit tier uses one representative local Git smoke and private
 * temporary files; the selected executable/producer are never executed here.
 */
const execute = promisify(execFile);
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
let temporary: string;
let checkout: string;
let dispatch: string;
let executable: string;
let env: NodeJS.ProcessEnv;
const producer = 'fixture_source = "canonical-producer"\n';
const interpreter = '#!/bin/sh\nexit 74\n';

beforeAll(async () => {
  temporary = await mkdtemp(path.join(os.tmpdir(), 'owner-publication-root-'));
  checkout = path.join(temporary, 'checkout');
  dispatch = path.join(temporary, 'account-dispatch');
  executable = path.join(temporary, 'configured-python');
  await Promise.all([mkdir(checkout, { mode: 0o700 }), mkdir(dispatch, { mode: 0o700 })]);
  await writeFile(executable, interpreter, { mode: 0o700 });
  env = { CINDY_OWNER_PUBLICATION_BRIDGE_ROOT: checkout, CINDY_OWNER_PUBLICATION_PYTHON: executable };
});
afterAll(async () => { if (temporary) await rm(temporary, { recursive: true, force: true }); });

describe('Main-only owner publication source', () => {
  it('does not inspect paths or create a source when configuration is absent', async () => {
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: 'unused', env: {} })).resolves.toBeUndefined();
  });

  it.each([
    { CINDY_OWNER_PUBLICATION_BRIDGE_ROOT: '/missing' },
    { CINDY_OWNER_PUBLICATION_PYTHON: '/missing' },
    { CINDY_OWNER_PUBLICATION_BRIDGE_ROOT: 'relative', CINDY_OWNER_PUBLICATION_PYTHON: '/missing' },
    { CINDY_OWNER_PUBLICATION_BRIDGE_ROOT: '/missing', CINDY_OWNER_PUBLICATION_PYTHON: 'python3' },
  ])('rejects incomplete or PATH-derived configuration with a path-free error', async settings => {
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env: settings }))
      .rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
  });

  it('rejects a directory without a real checkout', async () => {
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env }))
      .rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
  });

  it('pins one real Git snapshot and revokes dirty source, shadows, links, executable and config changes', async () => {
    // One local Git smoke covers the filesystem/Git boundary; no model,
    // renderer, publication transport, real account or network is involved.
    const git = (...args: string[]) => execute('git', ['-c', 'user.name=Source Fixture',
      '-c', 'user.email=source-fixture@example.invalid', '-c', 'commit.gpgSign=false', '-C', checkout, ...args],
    { env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null' } });
    await Promise.all(['bridge_core', 'scripts', 'config'].map(name => mkdir(path.join(checkout, name))));
    const sources = ['__init__', 'publication_owner_render', 'native_html_release', 'html_contract',
      'html_templates', 'html_design', 'report_publish_queue', 'report_secret_gate'];
    for (const name of sources) await writeFile(path.join(checkout, 'bridge_core', name + '.py'), producer);
    await writeFile(path.join(checkout, 'scripts', '__init__.py'), '');
    for (const name of ['publish_generic_html_direct', 'publish_worksheet_html'])
      await writeFile(path.join(checkout, 'scripts', name + '.py'), producer);
    for (const name of ['html_ui_contract', 'reserved_html_owners', 'bridge_shell_builders',
      'valerie_ivory_ui_contract', 'html_document_kinds'])
      await writeFile(path.join(checkout, 'config', name + '.json'), '{}\n');
    const policy = JSON.stringify({ reports: { public_base_url: 'https://reports.boulangerievalerie.com',
      remote_base_dir: '/www/wwwroot/reports.boulangerievalerie.com/reports' } });
    const policyFile = path.join(checkout, 'config', 'artifact_publish_policy.json');
    await writeFile(policyFile, policy);
    await git('init');
    await git('add', '--', '.');
    await git('commit', '-m', 'isolated source fixture');
    const pin = await resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env });
    expect(pin).toBeDefined();
    expect(pin!.root).toBe(checkout);
    expect(pin!.dispatchRoot).toBe(dispatch);
    expect(pin!.sourceIdentity).toMatch(/^[a-f0-9]{64}$/);
    expect(pin!.files['bridge_core/publication_owner_render.py']).toBe(digest(Buffer.from(producer)));
    expect(pin!.python.sha256).toBe(digest(Buffer.from(interpreter)));
    await expect(pin!.assertCurrent()).resolves.toBeUndefined();

    const producerFile = path.join(checkout, 'bridge_core', 'publication_owner_render.py');
    await writeFile(producerFile, producer + '# changed\n');
    await expect(pin!.assertCurrent()).rejects.toThrow(/^OWNER_PUBLICATION_SOURCE_CHANGED$/);
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env })).rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
    await writeFile(producerFile, producer);

    const shadow = path.join(checkout, 'json.py');
    await writeFile(shadow, 'raise RuntimeError("untrusted shadow")\n');
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env })).rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
    await rm(shadow);

    const outside = path.join(temporary, 'outside-producer.py');
    await writeFile(outside, producer);
    await rm(producerFile);
    await symlink(outside, producerFile, 'file');
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env })).rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
    await rm(producerFile);
    await writeFile(producerFile, producer);

    const selected = await resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env });
    env.CINDY_OWNER_PUBLICATION_BRIDGE_ROOT = path.join(temporary, 'different');
    await expect(selected!.assertCurrent()).rejects.toThrow(/^OWNER_PUBLICATION_SOURCE_CHANGED$/);
    env.CINDY_OWNER_PUBLICATION_BRIDGE_ROOT = checkout;
    const unchanged = await resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env });
    await writeFile(executable, interpreter + '# upgraded\n');
    await expect(unchanged!.assertCurrent()).rejects.toThrow(/^OWNER_PUBLICATION_SOURCE_CHANGED$/);
    const repinned = await resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env });
    expect(repinned!.sourceIdentity).not.toBe(pin!.sourceIdentity);
    await writeFile(executable, interpreter);
    await expect(unchanged!.assertCurrent()).rejects.toThrow(/^OWNER_PUBLICATION_SOURCE_CHANGED$/);
    expect((await resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env }))!.sourceIdentity).toBe(pin!.sourceIdentity);

    await chmod(dispatch, 0o755);
    if (process.platform !== 'win32')
      await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env })).rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
    await chmod(dispatch, 0o700);
    await writeFile(policyFile, JSON.stringify({ reports: { public_base_url: 'https://example.invalid',
      remote_base_dir: '/www/wwwroot/reports.boulangerievalerie.com/reports' } }));
    await git('add', '--', 'config/artifact_publish_policy.json');
    await git('commit', '-m', 'isolated wrong target');
    await expect(resolveOwnerPublicationRoot({ dispatchRoot: dispatch, env })).rejects.toThrow(/^OWNER_PUBLICATION_ROOT_UNAVAILABLE$/);
    expect(await readFile(executable, 'utf8')).toBe(interpreter);
  });
});
