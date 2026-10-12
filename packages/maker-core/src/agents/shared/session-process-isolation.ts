import path from 'node:path';

/** Host-owned, opt-in launch restriction for one concrete local transport.
 * No credentials, settings, or filesystem writes belong in this descriptor.
 * It must not be built from model input or reused for another process/session.
 */
export interface SessionProcessIsolation {
  readonly workingDirectory: string;
  readonly seatbeltProfile: string;
  /** Session runtime files only; authentication remains owned by the host. */
  readonly runtimeDirectory?: string;
}

/** Read only native base-URL overrides; never inspect headers or env credentials. */
export function localModelProxyEndpoints(args: readonly string[]): string[] {
  const endpoints: string[] = [];
  for (const value of args) {
    if (!/^model_providers\.[A-Za-z0-9_-]+\.base_url=/.test(value)) continue;
    const raw = value.slice(value.indexOf('=') + 1);
    try {
      const endpoint = new URL(raw.startsWith('"') ? JSON.parse(raw) : raw);
      if (endpoint.hostname === '127.0.0.1' && endpoint.protocol === 'http:' && endpoint.port
          && !endpoint.username && !endpoint.password) {
        endpoints.push(endpoint.origin);
      }
    } catch { /* Missing metadata must remain unavailable. */ }
  }
  return [...new Set(endpoints)];
}

/** Keep authentication/env assembly and process lifecycle with existing callers.
 * Unsupported or mismatched restrictions fail before spawn, never fall back to
 * an unrestricted launch. This primitive does not solve nested native sandboxes.
 */
export function isolatedLocalLaunch(
  command: string,
  args: readonly string[],
  cwd: string | undefined,
  isolation: SessionProcessIsolation | undefined,
  platform: string = process.platform,
): { command: string; args: string[] } {
  if (!isolation) return { command, args: [...args] };
  if (platform !== 'darwin') throw new Error('SESSION_PROCESS_ISOLATION_UNSUPPORTED');
  if (!cwd || !path.isAbsolute(cwd) || !path.isAbsolute(isolation.workingDirectory)
      || path.resolve(cwd) !== path.resolve(isolation.workingDirectory)) {
    throw new Error('SESSION_PROCESS_ISOLATION_DIRECTORY_MISMATCH');
  }
  if (!isolation.seatbeltProfile.trim() || isolation.seatbeltProfile.includes('\0')) {
    throw new Error('SESSION_PROCESS_ISOLATION_INVALID_PROFILE');
  }
  return {
    command: '/usr/bin/sandbox-exec',
    args: ['-p', isolation.seatbeltProfile, command, ...args],
  };
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

/** Call only with the final request payload at the existing outbound boundary.
 * The model ID comes from the host's frozen route, not arbitrary request text.
 * Never stringify input: header/credential/prompt fields are not inspected.
 * This is a projection helper, not evidence that a request has been transmitted.
 */
export function projectModelRequestParameters(payload: unknown, expectedModel: string): {
  model: string;
  effort: string;
  serviceTier: string;
} {
  const body = record(payload);
  const effort = record(body?.reasoning)?.effort;
  const tier = body?.service_tier;
  return {
    model: body?.model === expectedModel ? expectedModel : 'UNKNOWN',
    effort: typeof effort === 'string' && ['none', 'minimal', 'low', 'medium', 'high', 'xhigh'].includes(effort)
      ? effort : 'UNKNOWN',
    serviceTier: typeof tier === 'string' && ['auto', 'default', 'flex', 'priority'].includes(tier)
      ? tier : 'UNKNOWN',
  };
}
