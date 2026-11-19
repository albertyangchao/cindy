/** Shared CLI control connection; launchers supply the vetted binary and selected profile. */
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { cleanProcessEnv } from '@cindy/maker-core';
import { AccountServiceUnreachableError } from '../subscription-accounts/accountServiceError.js';

// Only used to classify; the CLI's own wording never leaves this module.
const UNREACHABLE_CLI_ERROR = /time(?:d)?\s*out|timeout|network|connect|dns|unreachable|sending request|tls|certificate|proxy|offline/i;

function codexRequestError(error: unknown): Error {
  const message = typeof (error as { message?: unknown })?.message === 'string'
    ? (error as { message: string }).message : '';
  return UNREACHABLE_CLI_ERROR.test(message)
    ? new AccountServiceUnreachableError('Codex account request failed')
    : new Error('Codex account request failed');
}

function codexProfileEnv(directory: string): Record<string, string> {
  const env = { ...cleanProcessEnv() };
  const replaced = new Set([
    'CODEX_HOME',
    'CODEX_ACCESS_TOKEN',
    'CODEX_API_KEY',
    'OPENAI_API_KEY',
    'OPENAI_BASE_URL',
    'OPENAI_FEDERATION_RULE_ID',
    'OPENAI_IDENTITY_TOKEN_FILE',
    'OPENAI_WORKLOAD_IDENTITY_CONTEXT',
  ]);
  for (const key of Object.keys(env)) if (replaced.has(key.toUpperCase())) delete env[key];
  env.CODEX_HOME = directory;
  return env;
}

export function codexAccountControlRpc(
  binary: string, directory: string, method: string, params: unknown,
  canDispatch?: () => boolean | Promise<boolean>, signal?: AbortSignal,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('Codex account request cancelled')); return; }
    const child = spawn(binary, ['app-server'], {
      cwd: homedir(),
      env: codexProfileEnv(directory),
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true,
    });
    let settled = false;
    let buffer = '';
    const finish = (error?: Error, result?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      child.kill();
      if (error) reject(error);
      else resolve(result);
    };
    // A stalled read is almost always the CLI waiting on its account service (startup refreshes).
    const timer = setTimeout(() => finish(new AccountServiceUnreachableError('Codex account read timed out')), 15_000);
    const abort = () => finish(new Error('Codex account request cancelled'));
    signal?.addEventListener('abort', abort, { once: true });
    const send = (message: unknown) => child.stdin.write(JSON.stringify(message) + '\n');
    const dispatch = async () => {
      try {
        if (canDispatch) {
          const allowed = canDispatch();
          // Existing synchronous proofs and the write must stay in the same synchronous segment.
          if (!(typeof allowed === 'boolean' ? allowed : await allowed))
            return finish(new Error('Codex account changed before dispatch'));
        }
        // An asynchronous credential/source check can outlive this control connection.
        if (!settled) send({ id: 2, method, params });
      } catch {
        finish(new Error('Codex account changed before dispatch'));
      }
    };
    child.stdin.on('error', () => finish(new Error('Codex account connection closed')));
    child.on('error', () => finish(new Error('Codex CLI unavailable')));
    child.on('close', () => finish(new Error('Codex account connection closed')));
    child.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > 1_048_576) return finish(new Error('Codex account response too large'));
      let newline: number;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        let message: { id?: number; error?: unknown; result?: unknown };
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        if (message.error) return finish(codexRequestError(message.error));
        if (message.id === 1) {
          send({ method: 'initialized', params: {} });
          // Startup may await configuration/auth refresh. A reset must still use
          // the exact credential observed before spawning this control connection.
          void dispatch();
        } else if (message.id === 2) finish(undefined, message.result);
      }
    });
    send({
      id: 1,
      method: 'initialize',
      params: {
        clientInfo: { name: 'cindy', version: '1.0.0' },
        capabilities: { experimentalApi: true },
      },
    });
  });
}

const refreshes = new Map<string, Promise<unknown>>();
/** One official token renewal per selected profile, shared with task token reads.
 * Each waiter re-reads its own account and authorization proof after renewal.
 * The bounded producer outlives a cancelled waiter; it never makes model requests. */
export function refreshCodexAccountTokens(binary: string, directory: string,
  canDispatch?: () => boolean | Promise<boolean>): Promise<unknown> {
  const key = JSON.stringify([binary, directory]);
  const existing = refreshes.get(key);
  if (existing) return existing;
  const pending = codexAccountControlRpc(binary, directory, 'account/read', { refreshToken: true }, canDispatch)
    .finally(() => { if (refreshes.get(key) === pending) refreshes.delete(key); });
  refreshes.set(key, pending);
  return pending;
}
