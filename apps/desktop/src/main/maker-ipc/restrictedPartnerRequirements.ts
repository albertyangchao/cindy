import { createHash } from 'node:crypto';
export interface PartnerRequirements {
  version: 1;
  revision: number;
  principalId: string;
  addressHashes: string[];
  source: { registry: string; nativeConfig: string; overlays: string[] };
  tools: string[];
  purposes: string[];
  media: string[];
}
const allowedTools = [
  'channel-history',
  'native-code-analysis',
  'readonly-research',
  'memory-read',
  'memory-write',
  'workspace-read',
  'workspace-search',
  'notes-search',
];
export const requirementHash = (r: PartnerRequirements) =>
  createHash('sha256').update(JSON.stringify(r)).digest('hex');
export function validateRequirements(value: unknown): asserts value is PartnerRequirements {
  const r = value as PartnerRequirements;
  const hex = (x: unknown) => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
  const list = (x: unknown, allowed?: string[]) =>
    Array.isArray(x) &&
    x.length > 0 &&
    x.length <= 16 &&
    new Set(x).size === x.length &&
    x.every((v) => typeof v === 'string' && (!allowed || allowed.includes(v)));
  if (
    !r ||
    Array.isArray(r) ||
    Object.keys(r).sort().join(',') !==
      'addressHashes,media,principalId,purposes,revision,source,tools,version' ||
    r.version !== 1 ||
    !Number.isSafeInteger(r.revision) ||
    r.revision < 1 ||
    !hex(r.principalId) ||
    !list(r.addressHashes) ||
    !r.addressHashes.every(hex) ||
    !r.source ||
    Object.keys(r.source).sort().join(',') !== 'nativeConfig,overlays,registry' ||
    !hex(r.source.registry) ||
    !hex(r.source.nativeConfig) ||
    !list(r.source.overlays) ||
    !r.source.overlays.every(hex) ||
    !list(r.tools, allowedTools) ||
    !list(r.purposes, ['workspace', 'notes', 'memory']) ||
    !list(r.media, ['vision', 'draw', 'edit', 'stt', 'tts'])
  )
    throw Error('RESTRICTED_PARTNER_REQUIREMENTS_INVALID');
}
export type ResourceCoverage = Partial<Record<'workspace' | 'notes' | 'memory', string[]>>;
export function requirementGaps(
  r: PartnerRequirements,
  facts: { tools: string[]; coverage: ResourceCoverage; memory?: boolean; history?: boolean },
): string[] {
  const missing: string[] = [];
  const tool: Record<string, string> = {
    'workspace-read': 'partner_resource_read',
    'workspace-search': 'partner_resource_search',
    'notes-search': 'partner_notes_search',
    'memory-read': 'partner_memory_search',
    'memory-write': 'partner_memory',
    'channel-history': 'partner_history',
    'native-code-analysis': 'native_codex_readonly',
    'readonly-research': 'partner_research',
  };
  for (const t of r.tools) if (!facts.tools.includes(tool[t])) missing.push(t);
  for (const purpose of r.purposes)
    if (!facts.coverage[purpose as keyof ResourceCoverage]?.length)
      missing.push('resource-' + purpose);
  if (facts.memory === false) missing.push('memory-policy');
  if (facts.history === false) missing.push('channel-history');
  return [...new Set(missing)];
}

export const grantResourceFingerprint = (g: {
  resourceIds: string[];
  resourceCoverage?: ResourceCoverage;
  requirements?: PartnerRequirements;
  media?: unknown;
  legacyMemory?: unknown;
  modelRoute?: unknown;
}) =>
  createHash('sha256')
    .update(
      JSON.stringify([
        g.resourceIds,
        g.resourceCoverage ?? {},
        g.requirements ?? null,
        g.media ?? {},
        g.legacyMemory ?? null,
        g.modelRoute ?? null,
      ]),
    )
    .digest('hex');
