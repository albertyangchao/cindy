import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import type { OwnerPublicationRoot } from './ownerPublicationRuntime.js';

const execute = promisify(execFile);
const rootVariable = 'CINDY_OWNER_PUBLICATION_BRIDGE_ROOT';
const pythonVariable = 'CINDY_OWNER_PUBLICATION_PYTHON';
const publicOrigin = 'https://reports.boulangerievalerie.com';
const remoteRoot = '/www/wwwroot/reports.boulangerievalerie.com/reports';
const requiredFiles = [
  'bridge_core/__init__.py',
  'bridge_core/publication_owner_render.py',
  'bridge_core/native_html_release.py',
  'bridge_core/html_contract.py',
  'bridge_core/html_templates.py',
  'bridge_core/html_design.py',
  'bridge_core/report_publish_queue.py',
  'bridge_core/report_secret_gate.py',
  'scripts/publish_generic_html_direct.py',
  'scripts/publish_worksheet_html.py',
  'config/artifact_publish_policy.json',
  'config/html_ui_contract.json',
  'config/reserved_html_owners.json',
  'config/bridge_shell_builders.json',
  'config/valerie_ivory_ui_contract.json',
  'config/html_document_kinds.json',
] as const;
const hash = (value: Buffer | string) => createHash('sha256').update(value).digest('hex');
const denied = (): never => { throw Error('OWNER_PUBLICATION_ROOT_UNAVAILABLE'); };
const requireThat: (value: unknown) => asserts value = value => { if (!value) denied(); };
const own = (uid: number) => !process.getuid || uid === process.getuid();
const sourceFile = (relative: string) =>
  (relative.endsWith('.py') && (!relative.includes('/') || /^(bridge_core|scripts)\//.test(relative))) ||
  /^bridge_core\/runtime_contracts\/.+\.json$/.test(relative) ||
  (requiredFiles as readonly string[]).includes(relative);

/** Hidden deployment configuration, consumed only by Main's account-bound factory.
 * Both values must be explicit absolute local paths; absent values disable this
 * path. They select source/interpreter, never an owner identity or a permission.
 * The caller supplies an existing private directory under its active account's
 * userData. No IPC, plugin preference, message or model argument reaches here.
 */
export interface OwnerPublicationRootOptions {
  dispatchRoot: string;
  env?: NodeJS.ProcessEnv;
}

interface Snapshot {
  root: string;
  dispatchRoot: string;
  publicOrigin: string;
  sourceIdentity: string;
  files: Record<string, string>;
  python: { path: string; sha256: string };
}

function configuration(env: NodeJS.ProcessEnv): readonly [string, string] | undefined {
  const selectedRoot = env[rootVariable], selectedPython = env[pythonVariable];
  if (selectedRoot === undefined && selectedPython === undefined) return undefined;
  requireThat(typeof selectedRoot === 'string' && typeof selectedPython === 'string');
  requireThat(selectedRoot.length > 0 && selectedRoot === selectedRoot.trim() && !selectedRoot.includes('\0'));
  requireThat(selectedPython.length > 0 && selectedPython === selectedPython.trim() && !selectedPython.includes('\0'));
  requireThat(path.isAbsolute(selectedRoot) && path.isAbsolute(selectedPython));
  return [selectedRoot, selectedPython];
}

async function directory(candidate: string, privateDirectory = false): Promise<string> {
  requireThat(path.isAbsolute(candidate));
  const before = await lstat(candidate);
  requireThat(before.isDirectory() && !before.isSymbolicLink() && own(before.uid));
  requireThat(!(before.mode & (privateDirectory ? 0o077 : 0o022)));
  const resolved = await realpath(candidate), after = await lstat(candidate);
  requireThat(before.dev === after.dev && before.ino === after.ino && before.ctimeMs === after.ctimeMs);
  return resolved;
}

async function readStable(file: string, limit: number, systemOwned = false): Promise<Buffer> {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    requireThat(before.isFile() && before.nlink === 1 && before.size <= limit);
    requireThat(!(before.mode & 0o022) && (own(before.uid) || (systemOwned && before.uid === 0)));
    const bytes = await handle.readFile(), after = await handle.stat();
    requireThat(bytes.length === before.size && before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs);
    const visible = await lstat(file);
    requireThat(!visible.isSymbolicLink() && visible.dev === after.dev && visible.ino === after.ino &&
      visible.size === after.size && visible.mtimeMs === after.mtimeMs && visible.ctimeMs === after.ctimeMs);
    return bytes;
  } finally { await handle.close(); }
}

async function git(root: string, ...args: string[]): Promise<string> {
  const result = await execute('git', ['-c', 'core.fsmonitor=false', '-C', root, ...args], {
    encoding: 'utf8', timeout: 10000, maxBuffer: 16 * 1024 * 1024,
    // Do not accept inherited Git overrides or replacement objects as the
    // selected checkout. These read-only commands cannot run hooks or filters.
    env: {
      PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
      LANG: 'C', LC_ALL: 'C', GIT_OPTIONAL_LOCKS: '0', GIT_NO_REPLACE_OBJECTS: '1',
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    },
  });
  return result.stdout;
}

async function inventory(root: string): Promise<string[]> {
  const found: string[] = [];
  for (const item of await readdir(root, { withFileTypes: true })) {
    const name = item.name;
    if (name.endsWith('.py')) {
      requireThat(item.isFile() && !item.isSymbolicLink());
      found.push(name);
    } else if (/\.(pyc|pyo|pyd|so)$/.test(name)) denied();
    else if (item.isDirectory() && !['bridge_core', 'scripts', '.git'].includes(name)) {
      // A newly introduced top-level package could shadow a standard-library
      // import after the canonical producer adds its checkout to sys.path.
      if (/^[A-Za-z_]\w*$/.test(name)) {
        const children = await readdir(path.join(root, name));
        requireThat(name === 'tests' || !children.some(child => /^__init__(?:\..*)?\.(py|pyc|pyo|pyd|so)$/.test(child)));
      }
    } else if (item.isSymbolicLink()) {
      // Source packages and top-level Python modules may never be links.
      requireThat(!/^[A-Za-z_]\w*$/.test(name));
    }
  }
  const walk = async (relative: string): Promise<void> => {
    const full = path.join(root, ...relative.split('/'));
    requireThat(await directory(full) === full);
    for (const item of await readdir(full, { withFileTypes: true })) {
      if (item.name === '__pycache__') continue; // producer redirects bytecode lookup to os.devnull
      const child = relative + '/' + item.name;
      requireThat(!item.isSymbolicLink());
      if (item.isDirectory()) await walk(child);
      else if (sourceFile(child)) {
        requireThat(item.isFile());
        found.push(child);
      } else if (/\.(pyc|pyo|pyd|so)$/.test(item.name)) denied();
    }
  };
  await walk('bridge_core');
  await walk('scripts');
  requireThat(await directory(path.join(root, 'config')) === path.join(root, 'config'));
  for (const file of requiredFiles.filter(file => file.startsWith('config/'))) found.push(file);
  return [...new Set(found)].sort();
}

async function snapshot(selected: readonly [string, string], dispatch: string): Promise<Snapshot> {
  const root = await directory(selected[0]), dispatchRoot = await directory(dispatch, true);
  const relativeDispatch = path.relative(root, dispatchRoot);
  requireThat(relativeDispatch !== '' && (relativeDispatch.startsWith('..' + path.sep) || path.isAbsolute(relativeDispatch)));
  requireThat(path.resolve((await git(root, 'rev-parse', '--show-toplevel')).trim()) === root);
  const commit = (await git(root, 'rev-parse', '--verify', 'HEAD^{commit}')).trim();
  requireThat(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commit));
  const entries = (await git(root, 'ls-tree', '-rz', '--full-tree', commit)).split('\0').filter(Boolean);
  const expected = new Map<string, string>();
  for (const entry of entries) {
    const match = /^(\d{6}) (\w+) ([a-f0-9]+)\t([^\0]+)$/.exec(entry);
    requireThat(match);
    const [, mode, kind, blob, name] = match;
    if (!sourceFile(name)) continue;
    requireThat(kind === 'blob' && ['100644', '100755'].includes(mode));
    requireThat(!name.includes('\\') && !name.split('/').some(piece => !piece || piece === '.' || piece === '..'));
    expected.set(name, blob);
  }
  requireThat(requiredFiles.every(file => expected.has(file)));
  const actual = await inventory(root), names = [...expected.keys()].sort();
  requireThat(JSON.stringify(actual) === JSON.stringify(names));
  const files: Record<string, string> = {};
  let policy: unknown;
  for (const name of names) {
    const bytes = await readStable(path.join(root, ...name.split('/')), 12 * 1024 * 1024);
    const blob = createHash(commit.length === 40 ? 'sha1' : 'sha256')
      .update('blob ' + bytes.length + '\0').update(bytes).digest('hex');
    // Do not trust index flags (assume-unchanged/skip-worktree), a clean status,
    // or caller-provided hashes in place of actual selected Git object bytes.
    requireThat(blob === expected.get(name));
    files[name] = hash(bytes);
    if (name === 'config/artifact_publish_policy.json') policy = JSON.parse(bytes.toString('utf8'));
  }
  requireThat(policy !== null && typeof policy === 'object' && !Array.isArray(policy));
  const reports = (policy as Record<string, unknown>).reports;
  requireThat(reports !== null && typeof reports === 'object' && !Array.isArray(reports));
  requireThat((reports as Record<string, unknown>).public_base_url === publicOrigin &&
    (reports as Record<string, unknown>).remote_base_dir === remoteRoot);
  const pythonPath = await realpath(selected[1]), pythonStat = await lstat(pythonPath);
  requireThat(pythonStat.isFile() && !pythonStat.isSymbolicLink() && (process.platform === 'win32' || !!(pythonStat.mode & 0o111)));
  const python = { path: pythonPath, sha256: hash(await readStable(pythonPath, 128 * 1024 * 1024, true)) };
  requireThat((await git(root, 'rev-parse', '--verify', 'HEAD^{commit}')).trim() === commit);
  requireThat(await directory(selected[0]) === root && await directory(dispatch, true) === dispatchRoot);
  requireThat(await realpath(selected[1]) === pythonPath && JSON.stringify(await inventory(root)) === JSON.stringify(names));
  return {
    root, dispatchRoot, publicOrigin, files, python,
    sourceIdentity: hash(JSON.stringify(['owner-publication-source/v1', root, dispatchRoot, commit, files, python, publicOrigin])),
  };
}

/** Pin a real, stable checkout without executing Python or publishing anything.
 * Every call revalidates the selection. The returned current check also catches
 * a changed environment, new import shadow, checkout move or interpreter change
 * before the runtime may use an already approved action.
 */
export async function resolveOwnerPublicationRoot(options: OwnerPublicationRootOptions): Promise<OwnerPublicationRoot | undefined> {
  const environment = () => options.env ?? process.env;
  try {
    const selected = configuration(environment());
    if (!selected) return undefined;
    const current = await snapshot(selected, options.dispatchRoot);
    requireThat(JSON.stringify(configuration(environment())) === JSON.stringify(selected));
    let revoked = false;
    return Object.freeze({
      ...current, files: Object.freeze(current.files), python: Object.freeze(current.python),
      async assertCurrent() {
        try {
          requireThat(!revoked);
          requireThat(JSON.stringify(configuration(environment())) === JSON.stringify(selected));
          const next = await snapshot(selected, options.dispatchRoot);
          requireThat(next.sourceIdentity === current.sourceIdentity);
          requireThat(JSON.stringify(configuration(environment())) === JSON.stringify(selected));
        } catch {
          revoked = true;
          throw Error('OWNER_PUBLICATION_SOURCE_CHANGED');
        }
      },
    });
  } catch { return denied(); }
}
