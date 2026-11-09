import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ResidentGhostRestart } from '../ResidentGhostRestart.js';
import type { GhostRuntimeState } from '../GhostRuntime.js';

/** Test value / W0 launch PLAN 04, unit tier:
 * Real recovery policy; observable result is whether the resident startup
 * boundary executes. Existing GhostRuntime tests have no restart scheduler.
 * Minimal regression: crash -> explicit stop during backoff -> delayed wake.
 * Main's installed-instance lookup is an injected external boundary here;
 * GhostRuntime.test.ts separately exercises the real failed-install guard.
 * Fake clocks avoid actual waits, process launches and user state.
 */
function setup() {
  let state: GhostRuntimeState = 'crashed';
  let owner = 'owner-a:1';
  let install = 'install-a';
  let enabled = true;
  const starts: string[] = [];
  const onError = vi.fn();
  const current = vi.fn(() => state === 'crashed' && enabled ? {
    identity: `${owner}/${install}`,
    restart: () => { starts.push(`${owner}/${install}`); state = 'starting'; },
  } : null);
  const recovery = new ResidentGhostRestart({ current, onError });
  const transition = (next: GhostRuntimeState) => { state = next; recovery.onStateChanged('demo', next); };
  return { recovery, starts, current, onError, transition,
    setOwner: (value: string) => { owner = value; },
    setInstall: (value: string) => { install = value; },
    disable: () => { enabled = false; },
  };
}

describe('resident crash recovery', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(0); });
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

  it('waits for backoff and coalesces duplicate crash notifications', async () => {
    const h = setup();
    h.transition('crashed'); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(999);
    expect(h.starts).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.starts).toEqual(['owner-a:1/install-a']);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(h.starts).toHaveLength(1);
  });

  it.each(['off', 'stopping', 'fused'] as const)('never wakes a resident after %s during backoff', async state => {
    const h = setup();
    h.transition('crashed'); h.transition(state);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(h.starts).toEqual([]);
  });

  it.each(['disabled', 'install', 'owner', 'owner-generation'] as const)('rechecks %s before executing delayed startup', async change => {
    const h = setup(); h.transition('crashed');
    if (change === 'disabled') h.disable();
    if (change === 'install') h.setInstall('install-b');
    if (change === 'owner') h.setOwner('owner-b:1');
    if (change === 'owner-generation') h.setOwner('owner-a:2');
    await vi.advanceTimersByTimeAsync(1_000);
    expect(h.starts).toEqual([]);
  });

  it('retains a bounded rolling budget across brief successful starts', async () => {
    const h = setup(); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(1_000);
    h.transition('starting'); h.transition('running'); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(1_999);
    expect(h.starts).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    h.transition('starting'); h.transition('running'); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(5_000);
    expect(h.starts).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(60_000);
    h.transition('starting'); h.transition('running'); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(1_000);
    expect(h.starts).toHaveLength(3);
  });

  it('cancels a pending retry when another caller already starts the resident', async () => {
    const h = setup(); h.transition('crashed'); h.transition('starting'); h.transition('running');
    await vi.advanceTimersByTimeAsync(5_000);
    expect(h.starts).toEqual([]);
  });

  it('ignores a cancelled timer when the same id crashes again', async () => {
    const h = setup(); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(500);
    h.transition('off'); h.transition('starting'); h.transition('running'); h.transition('crashed');
    await vi.advanceTimersByTimeAsync(500);
    expect(h.starts).toEqual([]);
    await vi.advanceTimersByTimeAsync(500);
    expect(h.starts).toHaveLength(1);
  });

  it('holds source failures without a retry loop or unhandled timer rejection', async () => {
    const h = setup(); h.transition('crashed');
    h.current.mockImplementation(() => { throw new Error('lookup unavailable'); });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(h.starts).toEqual([]);
    expect(h.onError).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });
});
