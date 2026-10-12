import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';

import type { SpawnOptions, SpawnedProcess } from '@anthropic-ai/claude-agent-sdk';
import { isolatedLocalLaunch, type SessionProcessIsolation } from '../shared/session-process-isolation.js';

export interface ObservedClaudeProcessOptions {
  /** Trusted host-only restriction; env/auth and observer lifecycle stay unchanged. */
  processIsolation?: SessionProcessIsolation;
  spawnOptions: SpawnOptions;
  registerProcess?: (pid: number) => void | (() => void);
  trackDebugFile?: () => () => void;
  onStderr?: (chunk: string) => void;
}

/** Mirror the SDK's local spawn while exposing one concrete process generation. */
export function spawnObservedClaudeProcess(
  opts: ObservedClaudeProcessOptions,
): SpawnedProcess {
  const launch = isolatedLocalLaunch(opts.spawnOptions.command, opts.spawnOptions.args,
    opts.spawnOptions.cwd, opts.processIsolation);
  const child: ChildProcessWithoutNullStreams = spawn(
    launch.command,
    launch.args,
    {
      cwd: opts.spawnOptions.cwd,
      env: opts.spawnOptions.env,
      signal: opts.spawnOptions.signal,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    },
  );
  let disposeRegistration: (() => void) | undefined;
  let disposeDebugFile: (() => void) | undefined;
  if (child.pid != null && child.pid > 0) {
    try {
      const dispose = opts.registerProcess?.(child.pid);
      if (typeof dispose === 'function') disposeRegistration = dispose;
    } catch {
      // Observation failures must not block Claude startup. Missing registry state
      // only makes this process fail closed for termination.
    }
    try { disposeDebugFile = opts.trackDebugFile?.(); } catch { /* diagnostics are best effort */ }
  }

  let registrationDisposed = false;
  const disposeOnce = (): void => {
    if (registrationDisposed) return;
    registrationDisposed = true;
    try { disposeRegistration?.(); } catch { /* best-effort cleanup */ }
    try { disposeDebugFile?.(); } catch { /* best-effort diagnostics */ }
    disposeDebugFile = undefined;
    disposeRegistration = undefined;
  };
  child.once('exit', disposeOnce);
  child.once('error', disposeOnce);
  child.stderr.on('data', (chunk: Buffer) => {
    // A custom SDK spawn owns stderr forwarding. Always drain the pipe so verbose
    // Claude output cannot deadlock when no callback is installed.
    opts.onStderr?.(chunk.toString('utf8'));
  });
  return child;
}
