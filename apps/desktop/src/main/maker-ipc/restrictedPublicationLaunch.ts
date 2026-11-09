/** Deployment-only launch switch. This status never grants publication authority.
 * D2 ships partner HTML as attachments and leaves owner HTML on its existing
 * Bridge route. The complete restricted publisher remains opt-in after launch.
 */
export const restrictedPublicationLaunchEnvironment = 'CINDY_RESTRICTED_PUBLICATION_ENABLED';
const deferredGates = Object.freeze([
  'ci-producer', 'coverage', 'owner-registry', 'kb', 'os-owner-census',
] as const);
export interface RestrictedPublicationLaunchPolicy {
  readonly schema: 'restricted-publication-launch/v1';
  readonly enabled: boolean;
  readonly state: 'DEFERRED_POST_LAUNCH' | 'ENABLED';
  readonly deferredGates: readonly (typeof deferredGates[number])[];
}

/** Main's environment is the hidden deployment override; plugin/IPC arguments
 * cannot set it. Missing override follows the launch default without writing
 * configuration. Invalid overrides fail closed instead of silently enabling.
 */
export function readRestrictedPublicationLaunchPolicy(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): RestrictedPublicationLaunchPolicy {
  const value = environment[restrictedPublicationLaunchEnvironment];
  if (value !== undefined && !['', '0', 'false', '1', 'true'].includes(value))
    throw Error('RESTRICTED_PUBLICATION_CONFIGURATION_INVALID');
  const enabled = value === '1' || value === 'true';
  return Object.freeze({
    schema: 'restricted-publication-launch/v1', enabled,
    state: enabled ? 'ENABLED' : 'DEFERRED_POST_LAUNCH',
    deferredGates: enabled ? Object.freeze([]) : deferredGates,
  });
}

/** A feature gate only: every original private owner, coverage and effect check
 * must still succeed after this returns. Never substitute this for a receipt.
 */
export function requireRestrictedPublicationEnabled(): void {
  if (!readRestrictedPublicationLaunchPolicy().enabled)
    throw Error('RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH');
}
