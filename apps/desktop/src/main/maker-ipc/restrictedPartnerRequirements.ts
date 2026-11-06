import { createHash } from 'node:crypto';
export interface OriginalMemoryInventory {
  version: 1;
  evidenceRevision: number;
  evidenceHash: string;
  identityHash: string;
  rootHash: string;
  durableRootHash: string;
  files: Array<{
    name: 'PROFILE.md' | 'MEMORY.md' | 'INTERESTS.md';
    exists: boolean;
    sha256: string | null;
  }>;
  database: { state: 'present' | 'absent'; sha256: string | null };
}
export interface PartnerRequirements {
  version: 1;
  revision: number;
  principalId: string;
  addressHashes: string[];
  source: { registry: string; nativeConfig: string; overlays: string[] };
  tools: string[];
  purposes: string[];
  media: string[];
  sourceInventory?: OriginalMemoryInventory;
  excludedNamespaces?: string[];
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
  'durable-memory-read',
];
export const requirementHash = (r: PartnerRequirements | OriginalMemoryInventory) =>
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
    Object.keys(r).some(
      (k) =>
        ![
          'addressHashes',
          'media',
          'principalId',
          'purposes',
          'revision',
          'source',
          'tools',
          'version',
          'sourceInventory',
          'excludedNamespaces',
        ].includes(k),
    ) ||
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
    !list(r.purposes, ['workspace', 'notes', 'memory', 'durable-files']) ||
    !list(r.media, ['vision', 'draw', 'edit', 'stt', 'tts'])
  )
    throw Error('RESTRICTED_PARTNER_REQUIREMENTS_INVALID');
  if (r.sourceInventory) {
    validateOriginalInventory(r.sourceInventory);
    if (!r.addressHashes.includes(r.sourceInventory.identityHash))
      throw Error('RESTRICTED_PARTNER_REQUIREMENTS_INVALID');
  }
  if (
    r.excludedNamespaces &&
    (!Array.isArray(r.excludedNamespaces) ||
      r.excludedNamespaces.length > 16 ||
      r.excludedNamespaces.some(
        (x) => typeof x !== 'string' || !x || x.length > 128 || /[\x00-\x1f]/.test(x),
      ))
  )
    throw Error('RESTRICTED_PARTNER_REQUIREMENTS_INVALID');
}
export type ResourceCoverage = Partial<
  Record<'workspace' | 'notes' | 'memory' | 'durable-files', string[]>
>;
export function requirementGaps(
  r: PartnerRequirements,
  facts: { tools: string[]; coverage: ResourceCoverage; memory?: boolean; history?: boolean },
): string[] {
  const missing: string[] = [];
  const tool: Record<string, string> = {
    'workspace-read': 'partner_resource_read',
    'workspace-search': 'partner_resource_search',
    'notes-search': 'partner_notes_search',
    'durable-memory-read': 'partner_durable_memory',
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
  memorySources?: unknown;
}) =>
  createHash('sha256')
    .update(
      JSON.stringify([
        g.resourceIds,
        g.resourceCoverage ?? {},
        g.requirements ?? null,
        g.media ?? {},
        g.legacyMemory ?? null,
        g.memorySources ?? null,
        g.modelRoute ?? null,
      ]),
    )
    .digest('hex');

export function validateOriginalInventory(
  value: unknown,
): asserts value is OriginalMemoryInventory {
  const r = value as OriginalMemoryInventory;
  const hex = (s: unknown) => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
  if (
    !r ||
    Object.keys(r).sort().join(',') !==
      'database,durableRootHash,evidenceHash,evidenceRevision,files,identityHash,rootHash,version' ||
    r.version !== 1 ||
    !Number.isSafeInteger(r.evidenceRevision) ||
    r.evidenceRevision < 1 ||
    ![r.evidenceHash, r.identityHash, r.rootHash, r.durableRootHash].every(hex) ||
    !Array.isArray(r.files) ||
    r.files.length !== 3 ||
    new Set(r.files.map((f) => f.name)).size !== 3 ||
    r.files.some(
      (f) =>
        !['PROFILE.md', 'MEMORY.md', 'INTERESTS.md'].includes(f.name) ||
        Object.keys(f).sort().join(',') !== 'exists,name,sha256' ||
        typeof f.exists !== 'boolean' ||
        (f.exists ? !hex(f.sha256) : f.sha256 !== null),
    ) ||
    !r.database ||
    Object.keys(r.database).sort().join(',') !== 'sha256,state' ||
    !['present', 'absent'].includes(r.database.state) ||
    (r.database.state === 'present' ? !hex(r.database.sha256) : r.database.sha256 !== null)
  )
    throw Error('RESTRICTED_PARTNER_REQUIREMENTS_INVALID');
}
