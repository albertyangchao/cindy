import type { GhostRuntimeState } from './GhostRuntime.js';

interface ResidentRestartTarget {
  /** Current owner generation and exact installation, captured by Main. */
  identity: string;
  /** Uses the existing resident startup path, with its normal permission checks. */
  restart(): void;
}

interface RestartEntry {
  identity: string;
  attempts: number[];
  timer: ReturnType<typeof setTimeout> | null;
}

/** A bounded recovery policy for GhostRuntime, not a second runtime.
 * Only the failed resident is considered; tools/messages are never replayed.
 * Main resolves current authority again when the timer fires. GhostRuntime's
 * existing crash fuse remains authoritative and is never reset here.
 */
export class ResidentGhostRestart {
  private readonly entries = new Map<string, RestartEntry>();

  constructor(private readonly options: {
    current: (id: string) => ResidentRestartTarget | null;
    now?: () => number;
    onError?: (id: string) => void;
  }) {}

  onStateChanged(id: string, state: GhostRuntimeState): void {
    const previous = this.entries.get(id);
    if (state !== 'crashed') {
      if (previous?.timer !== null && previous?.timer !== undefined) {
        clearTimeout(previous.timer);
        previous.timer = null;
      }
      // Starting/running retain the rolling attempt budget; a brief successful
      // load must not turn a crash loop into unlimited immediate retries.
      if (state === 'off' || state === 'stopping' || state === 'fused') this.entries.delete(id);
      return;
    }

    let target: ResidentRestartTarget | null;
    try { target = this.options.current(id); }
    catch { this.cancel(id); this.options.onError?.(id); return; }
    if (!target) { this.cancel(id); return; }
    if (previous?.identity === target.identity && previous.timer !== null) return;
    if (previous?.timer !== null && previous?.timer !== undefined) clearTimeout(previous.timer);
    const now = (this.options.now ?? Date.now)();
    const attempts = previous?.identity === target.identity
      ? previous.attempts.filter(at => now >= at && now - at < 60_000)
      : [];
    const entry: RestartEntry = { identity: target.identity, attempts, timer: null };
    this.entries.set(id, entry);
    // The runtime fuses at three crashes in sixty seconds. At most two
    // automatic retries in that same interval, with one/two second backoff.
    const delay = [1_000, 2_000][attempts.length];
    if (delay === undefined) return;
    entry.attempts.push(now);
    entry.timer = setTimeout(() => {
      if (this.entries.get(id) !== entry) return;
      entry.timer = null;
      try {
        const current = this.options.current(id);
        if (this.entries.get(id) !== entry || current?.identity !== entry.identity) {
          this.cancel(id);
          return;
        }
        current.restart();
      } catch {
        // Do not turn an unexpected source/start error into a retry loop.
        this.cancel(id);
        this.options.onError?.(id);
      }
    }, delay);
  }

  private cancel(id: string): void {
    const entry = this.entries.get(id);
    if (entry?.timer !== null && entry?.timer !== undefined) clearTimeout(entry.timer);
    this.entries.delete(id);
  }
}
