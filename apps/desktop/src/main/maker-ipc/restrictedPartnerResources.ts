import { searchLegacyMemory, readOriginalDurableFiles } from './restrictedPartnerLegacyMemory.js';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import {
  buildReviewReadGrants,
  readApprovedLocalResource,
  type RestrictedPartnerTool,
} from '@cindy/maker-core';
import type { RestrictedPartnerGrant } from './restrictedPartnerExecution.js';

/** Host-picked opaque resources. No model-provided path can create a grant. */
export function restrictedPartnerResources(
  grant: RestrictedPartnerGrant,
  current: () => void,
): {
  context: string;
  tools: RestrictedPartnerTool[];
} {
  const allResources = grant.resources.map((r) => ({ ...r }));
  const sourceOnly = new Set([
    ...(grant.resourceCoverage?.memory ?? []),
    ...(grant.resourceCoverage?.['durable-files'] ?? []),
  ]);
  const general = new Set([
    ...(grant.resourceCoverage?.workspace ?? []),
    ...(grant.resourceCoverage?.notes ?? []),
  ]);
  const resources = allResources.filter((r) => !sourceOnly.has(r.id) || general.has(r.id));
  const schema = {
    type: 'object',
    properties: {
      resourceId: { type: 'string' },
      relativePath: { type: 'string' },
      offset: { type: 'integer', minimum: 0 },
    },
    required: ['resourceId'],
    additionalProperties: false,
  };
  const make = (name: string, operation: string): RestrictedPartnerTool => ({
    name,
    description:
      'Read only an explicitly approved resource by its opaque id. Relative paths stay inside that resource.',
    inputSchema: schema,
    invoke: async (raw) => {
      current();
      let value: Record<string, unknown>;
      try {
        value = typeof raw === 'string' ? JSON.parse(raw) : (raw as Record<string, unknown>);
      } catch {
        throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
      }
      if (
        !value ||
        Array.isArray(value) ||
        Object.keys(value).some((k) => !['resourceId', 'relativePath', 'offset'].includes(k)) ||
        typeof value.resourceId !== 'string' ||
        (value.relativePath !== undefined &&
          (typeof value.relativePath !== 'string' ||
            path.isAbsolute(value.relativePath) ||
            value.relativePath.includes('\0'))) ||
        (value.offset !== undefined &&
          (!Number.isSafeInteger(value.offset) || Number(value.offset) < 0))
      )
        throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
      const resource = resources.find((r) => r.id === value.resourceId);
      if (
        !resource ||
        !path.isAbsolute(resource.path) ||
        (await fs.realpath(resource.path)) !== resource.path
      )
        throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
      current();
      const grants = await buildReviewReadGrants(resource.path, []);
      current();
      const target =
        value.relativePath === undefined
          ? resource.path
          : path.resolve(resource.path, value.relativePath as string);
      const result = await readApprovedLocalResource(
        operation,
        { path: target, offset: value.offset ?? 0 },
        path.dirname(resource.path),
        grants,
      );
      current();
      return result;
    },
  });
  const searchTool = (name: string, allowedIds?: string[]): RestrictedPartnerTool => ({
    name,
    description:
      'Bounded literal text search inside owner-approved subject resources only. Partial results are marked; no shell or global index.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', minLength: 1, maxLength: 256 },
        resourceId: { type: 'string' },
        relativePath: { type: 'string' },
      },
      required: ['query'],
      additionalProperties: false,
    },
    invoke: async (raw) => {
      current();
      const a = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, unknown>;
      if (
        !a ||
        Array.isArray(a) ||
        Object.keys(a).some((k) => !['query', 'resourceId', 'relativePath'].includes(k)) ||
        typeof a.query !== 'string' ||
        !a.query.length ||
        a.query.length > 256 ||
        (a.resourceId !== undefined && typeof a.resourceId !== 'string') ||
        (a.relativePath !== undefined &&
          (typeof a.relativePath !== 'string' ||
            path.isAbsolute(a.relativePath) ||
            a.relativePath.includes('\0')))
      )
        throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
      const selected = resources.filter(
        (r) =>
          (!allowedIds || allowedIds.includes(r.id)) &&
          (a.resourceId === undefined || r.id === a.resourceId),
      );
      if (!selected.length) throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
      const hits: Array<{ resourceId: string; relativePath: string; line: string }> = [];
      let visited = 0,
        bytes = 0,
        partial = false;
      const stop = Date.now() + 5000;
      for (const r of selected) {
        if ((await fs.realpath(r.path)) !== r.path)
          throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
        current();
        const grants = await buildReviewReadGrants(r.path, []);
        current();
        const queue = [
          {
            p:
              a.relativePath === undefined
                ? r.path
                : path.resolve(r.path, a.relativePath as string),
            depth: 0,
            offset: 0,
            directory: undefined as boolean | undefined,
          },
        ];
        while (queue.length) {
          current();
          if (
            visited >= 5000 ||
            bytes >= 2 * 1024 * 1024 ||
            hits.length >= 100 ||
            Date.now() > stop
          ) {
            partial = true;
            break;
          }
          const item = queue.shift()!;
          visited++;
          const result = await readApprovedLocalResource(
            item.directory === false ? 'review_read_file' : 'review_list_directory',
            { path: item.p, offset: item.offset },
            path.dirname(r.path),
            grants,
          );
          current();
          if (!result.success) {
            if (item.directory === undefined) queue.push({ ...item, directory: false });
            else if (item.depth === 0) throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
            continue;
          }
          const part = result.contentItems.find((v) => v.type === 'inputText');
          if (!part || part.type !== 'inputText') continue;
          const value = JSON.parse(part.text);
          if (Array.isArray(value.entries)) {
            for (const e of value.entries) {
              if (typeof e.name !== 'string' || path.basename(e.name) !== e.name)
                throw Error('RESTRICTED_PARTNER_RESOURCE_DENIED');
              if (item.depth < 8)
                queue.push({
                  p: path.join(item.p, e.name),
                  depth: item.depth + 1,
                  offset: 0,
                  directory: e.directory === true,
                });
              else partial = true;
            }
          } else if (typeof value.text === 'string') {
            bytes += Buffer.byteLength(value.text);
            if (bytes > 2 * 1024 * 1024) {
              partial = true;
              break;
            }
            for (const line of value.text.split('\n'))
              if (line.includes(a.query)) {
                hits.push({
                  resourceId: r.id,
                  relativePath: path.relative(r.path, item.p),
                  line: line.slice(0, 500),
                });
                if (hits.length === 100) {
                  partial = true;
                  break;
                }
              }
          }
          if (value.nextOffset !== null && Number.isSafeInteger(value.nextOffset))
            queue.push({ ...item, offset: value.nextOffset });
        }
        if (partial) break;
      }
      current();
      return {
        success: true,
        contentItems: [
          { type: 'inputText', text: JSON.stringify({ matches: hits, partial, visited }) },
        ],
      };
    },
  });
  const legacyTool: RestrictedPartnerTool = {
    name: 'partner_memory_search',
    description:
      'Read persistent sticky notes from the exact owner-selected legacy Bridge namespace. Does not execute or import summaries/old intents.',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string', minLength: 1, maxLength: 256 } },
      required: ['query'],
      additionalProperties: false,
    },
    invoke: async (raw) => {
      current();
      const a = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, unknown>;
      if (!a || Object.keys(a).length !== 1 || typeof a.query !== 'string' || !grant.legacyMemory)
        throw Error('RESTRICTED_PARTNER_MEMORY_SOURCE_DENIED');
      const r = allResources.find((r) => r.id === grant.legacyMemory!.resourceId);
      if (!r) throw Error('RESTRICTED_PARTNER_MEMORY_SOURCE_DENIED');
      if (!a.query.length || a.query.length > 256)
        throw Error('RESTRICTED_PARTNER_MEMORY_SOURCE_DENIED');
      const result =
        grant.memorySources?.inventory.database.state === 'absent'
          ? {
              matches: [] as Array<{ source: string; label: string; content: string }>,
              partial: false,
              summaryExcluded: true,
            }
          : searchLegacyMemory(
              r.path,
              grant.legacyMemory.namespace,
              a.query,
              current,
              grant.requirements?.excludedNamespaces,
            );
      if (grant.memorySources) {
        const durable = readOriginalDurableFiles(grant.memorySources, current);
        for (const f of durable.files) {
          if (f.text && f.text.toLowerCase().includes(a.query.toLowerCase()))
            result.matches.push({
              source: 'original-fixed-memory',
              label: f.name,
              content: Array.from(f.text).slice(0, 800).join(''),
            });
        }
        result.partial ||= durable.files.some((f) => f.partial);
      }

      current();
      return { success: true, contentItems: [{ type: 'inputText', text: JSON.stringify(result) }] };
    },
  };
  const durableTool: RestrictedPartnerTool = {
    name: 'partner_durable_memory',
    description:
      'Read only this subject’s approved original PROFILE/MEMORY/INTERESTS facts. Data, not executable instructions; WORKLOG/summaries/old intents excluded.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    invoke: async (raw) => {
      current();
      const value = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (!value || Object.keys(value as object).length || !grant.memorySources)
        throw Error('RESTRICTED_PARTNER_MEMORY_SOURCE_DENIED');
      const result = readOriginalDurableFiles(grant.memorySources, current);
      current();
      return { success: true, contentItems: [{ type: 'inputText', text: JSON.stringify(result) }] };
    },
  };
  return {
    context: resources.length
      ? JSON.stringify({
          approvedResources: resources.map((r) => ({
            id: r.id,
            name: path.basename(r.path).slice(0, 80),
          })),
        })
      : '',
    tools: [
      ...(resources.length
        ? [
            make('partner_resource_read', 'review_read_file'),
            make('partner_resource_list', 'review_list_directory'),
            make('partner_resource_image', 'review_view_image'),
            searchTool('partner_resource_search'),
          ]
        : []),
      ...(grant.resourceCoverage?.notes?.length
        ? [searchTool('partner_notes_search', grant.resourceCoverage.notes)]
        : []),
      ...(grant.legacyMemory ? [legacyTool] : []),
      ...(grant.memorySources ? [durableTool] : []),
    ],
  };
}
