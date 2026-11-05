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
  const resources = grant.resources.map((r) => ({ ...r }));
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
  return {
    context: resources.length
      ? JSON.stringify({
          approvedResources: resources.map((r) => ({ id: r.id, name: path.basename(r.path).slice(0,80) })),
        })
      : '',
    tools: resources.length
      ? [
          make('partner_resource_read', 'review_read_file'),
          make('partner_resource_list', 'review_list_directory'),
          make('partner_resource_image', 'review_view_image'),
        ]
      : [],
  };
}
