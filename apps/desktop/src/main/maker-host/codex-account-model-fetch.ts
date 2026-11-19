import type { CodexModelListItem } from '@cindy/maker-core';
import { mapCodexModelsToCatalog } from './codexModelMapping.js';

export type CodexAccountModelItem = Partial<CodexModelListItem>;

/** Only the status is carried across the host boundary, never the upstream body. */
export class CodexAccountModelError extends Error {
  constructor(readonly status?: number) { super('Codex account model discovery failed'); }
}

/** Renew only a rejected credential, through the selected profile's existing CLI lifecycle. */
export async function fetchCodexAccountModelsWithRefresh(options: {
  clientVersion: string; fetch: typeof fetch; signal?: AbortSignal;
  isCurrent(): boolean | Promise<boolean>;
  readTokens(): Promise<{ accessToken: string; accountId: string | null; canDispatch(): boolean }>;
  refreshTokens(proof: () => boolean | Promise<boolean>): Promise<unknown>;
}) {
  let tokens = await options.readTokens();
  const accountId = tokens.accountId;
  if (!accountId) throw new CodexAccountModelError();
  const proof = () => {
    const allowed = options.isCurrent();
    return typeof allowed === 'boolean' ? allowed && !options.signal?.aborted && tokens.canDispatch()
      : allowed.then(value => value && !options.signal?.aborted && tokens.canDispatch());
  };
  const read = () => fetchCodexAccountModels({ ...options, accessToken: tokens.accessToken, accountId, isCurrent: proof });
  try {
    const result = await read();
    return { ...result, canDispatch: tokens.canDispatch };
  } catch (error) {
    if (!(error instanceof CodexAccountModelError) || error.status !== 401 || !await proof()) throw error;
    await options.refreshTokens(proof);
    if (options.signal?.aborted || !await options.isCurrent()) throw new CodexAccountModelError();
    tokens = await options.readTokens();
    if (tokens.accountId !== accountId) throw new CodexAccountModelError();
    const result = await read();
    return { ...result, canDispatch: tokens.canDispatch };
  }
}

/** Model discovery is an account HTTP read, not app-server's possibly bundled picker.
 * Credentials stay in the host; the caller supplies its existing revocation proof. */
export async function fetchCodexAccountModels(options: {
  accessToken: string;
  accountId: string;
  clientVersion: string;
  signal?: AbortSignal;
  isCurrent(): boolean | Promise<boolean>;
  fetch: typeof fetch;
}): Promise<{ data: CodexAccountModelItem[]; nextCursor: null }> {
  const before = options.isCurrent();
  if (options.signal?.aborted || !(typeof before === 'boolean' ? before : await before)) throw new Error('Codex model account changed');
  const url = new URL('https://chatgpt.com/backend-api/codex/models');
  url.searchParams.set('client_version', options.clientVersion);
  let response: Response | undefined;
  try {
    response = await options.fetch(url.toString(), {
      method: 'GET', redirect: 'error', signal: options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(15_000)]) : AbortSignal.timeout(15_000),
      headers: { authorization: `Bearer ${options.accessToken}`,
        'chatgpt-account-id': options.accountId, accept: 'application/json' },
    });
    if (!response.ok) throw new CodexAccountModelError(response.status);
    const reader = response.body?.getReader();
    if (!reader) throw new Error('Codex model discovery returned no body');
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
        if (bytes > 8 * 1024 * 1024) throw new Error('Codex model response exceeded limit');
        chunks.push(chunk.value);
      }
    } finally { await reader.cancel().catch(() => undefined); }
    const raw: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!raw || typeof raw !== 'object' || !Array.isArray((raw as { models?: unknown }).models))
      throw new Error('Invalid Codex model response');
    const members = (raw as { models: unknown[] }).models;
    if ((raw as { nextCursor?: unknown }).nextCursor || (raw as { has_more?: unknown }).has_more === true
      || members.length > 1_000 || members.some(model => !model || typeof model !== 'object'
      || typeof (model as { slug?: unknown }).slug !== 'string'
      || !(model as { slug: string }).slug.trim()
      || !['list', 'hide'].includes((model as { visibility?: string }).visibility ?? '')
      || typeof (model as { supported_in_api?: unknown }).supported_in_api !== 'boolean')) throw new Error('Invalid Codex model members');
    const after = options.isCurrent();
    if (options.signal?.aborted || !(typeof after === 'boolean' ? after : await after)) throw new Error('Codex model account changed');
    const data: CodexAccountModelItem[] = mapCodexModelsToCatalog(raw).sort((a, b) => (a.sortOrder ?? 50) - (b.sortOrder ?? 50)).map((model, index) => ({
      id: model.id, model: model.id, displayName: model.name ?? model.id,
      description: model.description ?? '', hidden: false, isDefault: index === 0,
      ...(model.discoveredMetadata?.efforts !== undefined ? {
        supportedReasoningEfforts: (model.efforts ?? []).map(reasoningEffort => ({ reasoningEffort, description: '' })),
      } : {}),
      ...(model.discoveredMetadata?.defaultEffort !== undefined ? {
        defaultReasoningEffort: model.discoveredMetadata.defaultEffort ?? 'none',
      } : {}),
      ...(model.supportsFastMode !== undefined ? {
        additionalSpeedTiers: [...(model.supportsFastMode ? ['fast'] : []),
          ...(model.supportsUltrafastMode ? ['ultrafast'] : [])], serviceTiers: [],
      } : {}),
      ...(model.contextWindowVerified ? { contextWindow: model.contextWindow, contextWindowVerified: true } : {}),
      ...(model.contextWindowMax !== undefined ? { contextWindowMax: model.contextWindowMax } : {}),
      ...(model.supportsImageInput !== undefined ? { supportsImageInput: model.supportsImageInput } : {}),
    }));
    return { data, nextCursor: null };
  } catch (error) {
    // Never let fetch errors, response bodies or credentials escape into logs/IPC.
    throw error instanceof CodexAccountModelError ? error : new CodexAccountModelError();
  } finally { await response?.body?.cancel().catch(() => undefined); }
}
