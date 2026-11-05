import type { ProxyOptions } from '@cindy/anthropic-compat-proxy';
/** Native app-server continuations/retries must revalidate, not only the initial turn/start. */
export function restrictedPartnerEgressGate(
  assertCurrent: () => void,
): NonNullable<ProxyOptions['revalidateBeforeDispatch']> {
  return (decision) => {
    try {
      assertCurrent();
    } catch {
      throw new Error('RESTRICTED_PARTNER_REVOKED');
    }
    if (decision?.localHandler) throw Error('RESTRICTED_PARTNER_ROUTE_UNSUPPORTED');
    return null; // Keep the original resolved route and all existing provider/credential guards.
  };
}

/** Applied last, after ordinary provider spawn arguments. */
export function restrictedPartnerSpawnArgs(providerIds: readonly string[]): string[] {
  if (providerIds.some((id) => !/^[a-zA-Z0-9_-]{1,160}$/.test(id)))
    throw Error('RESTRICTED_PARTNER_ROUTE_UNSUPPORTED');
  return [
    '-c',
    'features.code_mode_only=false',
    '-c',
    'features.code_mode=false',
    ...[...new Set(providerIds)].flatMap((id) => [
      '-c',
      `model_providers.${id}.request_max_retries=0`,
      '-c',
      `model_providers.${id}.stream_max_retries=0`,
      '-c',
      `model_providers.${id}.supports_websockets=false`,
    ]),
  ];
}
