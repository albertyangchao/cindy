/**
 * A Claude tool may launch a replacement Cindy from its inherited environment.
 * The CONNECT bridge belongs to the old host; it must never become the new
 * host's upstream. Carry only the values Cindy overrides, not the whole env.
 * This context may contain proxy credentials: never log or persist it.
 */
export const CLAUDE_CLI_PROXY_CONTEXT_ENV = 'CINDY_CLAUDE_CLI_PROXY_CONTEXT';

const LOOPBACK_NO_PROXY = 'localhost,127.0.0.1,::1';
const PROXY_KEYS = ['HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'] as const;
type ProxyKey = typeof PROXY_KEYS[number];
type Override = { key: ProxyKey; injected: string; previous: string | null };

export function buildClaudeCliProxyEnv(
  bridge: string,
  useLoopbackNoProxy: boolean,
  parentEnv: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  // Collapse an inherited generation on a copy; never snapshot a retiring
  // bridge as the parent route when another CLI layer injects a new bridge.
  const originalEnv: NodeJS.ProcessEnv = {};
  // Windows spawn folds aliases and keeps the first sorted key. A plain object
  // copy loses process.env's case-insensitive lookup, so normalize the snapshot
  // before a lowercase-only original could be deleted by its uppercase alias.
  const parentKeys = Object.keys(parentEnv).sort();
  for (const key of [...PROXY_KEYS, CLAUDE_CLI_PROXY_CONTEXT_ENV]) {
    const parentKey = platform === 'win32'
      ? parentKeys.find((name) => name.toUpperCase() === key.toUpperCase())
      : key;
    const value = parentKey === undefined ? undefined : parentEnv[parentKey];
    if (value !== undefined) originalEnv[key] = value;
  }
  restoreInheritedClaudeCliProxyEnv(originalEnv);
  const injected: Record<string, string> = {
    HTTPS_PROXY: bridge,
    https_proxy: bridge,
    ...(useLoopbackNoProxy ? { NO_PROXY: LOOPBACK_NO_PROXY, no_proxy: LOOPBACK_NO_PROXY } : {}),
  };
  const overrides = Object.entries(injected).map(([key, value]) => ({
    key,
    injected: value,
    previous: originalEnv[key] ?? null,
  }));
  return {
    ...injected,
    [CLAUDE_CLI_PROXY_CONTEXT_ENV]: JSON.stringify({ version: 1, overrides }),
  };
}

function parseOverrides(raw: string): Override[] | null {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || typeof value !== 'object') return null;
  const context = value as { version?: unknown; overrides?: unknown };
  if (context.version !== 1 || !Array.isArray(context.overrides)) return null;
  if (context.overrides.length !== 2 && context.overrides.length !== 4) return null;
  const entries: Override[] = [];
  const keys = new Set<string>();
  for (const item of context.overrides) {
    if (!item || typeof item !== 'object') return null;
    const entry = item as { key?: unknown; injected?: unknown; previous?: unknown };
    if (typeof entry.key !== 'string' || !PROXY_KEYS.includes(entry.key as ProxyKey)
      || keys.has(entry.key) || typeof entry.injected !== 'string'
      || !(entry.previous === null || typeof entry.previous === 'string')) return null;
    keys.add(entry.key);
    entries.push(entry as Override);
  }
  const bridge = entries.find((entry) => entry.key === 'HTTPS_PROXY')?.injected;
  const match = /^http:\/\/127\.0\.0\.1:([0-9]+)$/.exec(bridge ?? '');
  if (!match || Number(match[1]) < 1 || Number(match[1]) > 65535) return null;
  if (entries.find((entry) => entry.key === 'https_proxy')?.injected !== bridge) return null;
  if (entries.length === 4 && (!keys.has('NO_PROXY') || !keys.has('no_proxy'))) return null;
  if (entries.some((entry) => entry.key.toUpperCase() === 'NO_PROXY'
    && entry.injected !== LOOPBACK_NO_PROXY)) return null;
  return entries;
}

/**
 * Earliest Desktop startup only. Unmarked/invalid proxy settings remain intact,
 * even if the port is unavailable. No connectivity probe or DIRECT fallback.
 * Apply per-key comparisons so explicit settings made after injection survive.
 */
export function restoreInheritedClaudeCliProxyEnv(env: NodeJS.ProcessEnv = process.env): void {
  const raw = env[CLAUDE_CLI_PROXY_CONTEXT_ENV];
  if (raw === undefined) return;
  delete env[CLAUDE_CLI_PROXY_CONTEXT_ENV];
  const overrides = parseOverrides(raw);
  if (!overrides) return;
  // One case variant may have been explicitly overridden downstream. Remove
  // Cindy's other alias rather than resurrecting a parent value that could
  // shadow that explicit choice (curl/Node differ in alias precedence).
  const explicitGroups = new Set(overrides
    .filter((entry) => typeof env[entry.key] === 'string' && env[entry.key] !== entry.injected)
    .map((entry) => entry.key.toUpperCase()));
  for (const entry of overrides) {
    if (env[entry.key] !== entry.injected) continue;
    if (explicitGroups.has(entry.key.toUpperCase()) || entry.previous === null) {
      delete env[entry.key];
    } else {
      env[entry.key] = entry.previous;
    }
  }
}
