import type { AgentDeps, CodexModelListItem } from '@cindy/maker-core';
import { getActiveAppSession, isAppSessionBoundaryPending } from '../appSessionState.js';
import { mapCodexAppServerModelsToCatalog } from './codexModelMapping.js';
import { getCustomProvider, updateCustomProviderIfUnchanged } from './custom-provider-store.js';
import { setDiscoveredCodexModels } from './active-catalog.js';

export type CodexAccountModelSnapshot = { models: Partial<CodexModelListItem>[]; isCurrent(): boolean };

/** Shared Desktop/Node Host publication. The reader retains this exact credential's proof. */
export function createCodexLocalModelSink(
  refreshCustomProvidersIntoCatalog: () => Promise<unknown>,
  readModels: (providerId: string | undefined, guard: { signal: AbortSignal; isCurrent(): boolean }) => Promise<CodexAccountModelSnapshot>,
): NonNullable<AgentDeps['refreshCodexLocalModels']> {
  return async ({ providerId }, guard) => {
    const owner = getActiveAppSession();
    const independent = providerId && providerId !== 'openai' ? providerId : undefined;
    const current = () => !guard.signal.aborted && guard.isCurrent() && !isAppSessionBoundaryPending()
      && getActiveAppSession().generation === owner.generation;
    if (!current()) return false;
    const previous = independent ? await getCustomProvider(independent) : undefined;
    if (independent && (!previous?.runtimes.codex || previous.auth?.native !== 'codex')) return false;
    if (!current()) return false;
    const live = await readModels(independent, { ...guard, isCurrent: current });
    const canCommit = () => current() && live.isCurrent();
    if (!canCommit()) return false;
    const mapped = mapCodexAppServerModelsToCatalog(live.models);
    if (independent && previous?.runtimes.codex) {
      const next = { ...previous, runtimes: { codex: { ...previous.runtimes.codex,
        models: mapped.map(model => ({ id: model.id, name: model.name,
          supportsUltrafastMode: model.supportsUltrafastMode === true,
          ...(model.contextWindowVerified ? { contextWindow: model.contextWindow } : {}),
          discoveredMetadata: model.discoveredMetadata,
        })),
      } } };
      const applied = await updateCustomProviderIfUnchanged(independent, previous, next, Date.now(), canCommit);
      if (!canCommit()) return false;
      if (applied) await refreshCustomProvidersIntoCatalog();
      return applied;
    }
    setDiscoveredCodexModels(mapped, { source: 'list' });
    return true;
  };
}
