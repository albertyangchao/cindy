import path from 'node:path';
import type { CodexModelListItem } from '@cindy/maker-core';
import type { CodexAccountModelSnapshot } from './codexLocalModelSink.js';
import { currentCodexCredentialGeneration } from './codexCredentialRead.js';
import { codexAccountRpc } from '../subscription-accounts/nativeCli.js';
import { getCodexHome } from './codex-home-path.js';
import { codexAccountHome, codexAccountState, isCodexAccountLoginActive } from './codex-account-auth.desktop.js';
import { captureNativeProviderAuthorizationGeneration, isNativeProviderAuthBound } from './nativeProviderAuthBinding.js';
import { shouldSuppressLocalCodexAuth } from './codex-auth-invalidation.js';

/** Desktop binding/revocation gates; discovery itself uses the launcher's transport. */
export async function readCodexAccountModels(providerId: string | undefined, guard: { signal: AbortSignal; isCurrent(): boolean }): Promise<CodexAccountModelSnapshot> {
  const home = providerId ? codexAccountHome(providerId) : getCodexHome();
  const authorization = () => providerId
    ? JSON.stringify(currentCodexCredentialGeneration(path.join(home, 'account.json')))
    : captureNativeProviderAuthorizationGeneration('openai');
  const generation = authorization();
  const allowed = () => !guard.signal.aborted && guard.isCurrent() && generation === authorization() && (providerId ? !isCodexAccountLoginActive(providerId) && codexAccountState(providerId).authenticated
    : isNativeProviderAuthBound('openai') && !shouldSuppressLocalCodexAuth(home, path.join(home, 'auth.json')));
  if (!allowed()) throw new Error('Codex model account changed');
  const result = await codexAccountRpc(home, 'model/list', {}, allowed, guard.signal) as { data: Partial<CodexModelListItem>[]; canDispatch(): boolean };
  if (!allowed()) throw new Error('Codex model account changed');
  return { models: result.data, isCurrent: () => allowed() && result.canDispatch() };
}
