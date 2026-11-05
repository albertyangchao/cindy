import type { ProxyOptions } from '@cindy/anthropic-compat-proxy';
/** Native app-server continuations/retries must revalidate, not only the initial turn/start. */
export function restrictedPartnerEgressGate(
  assertCurrent: () => void,
): NonNullable<ProxyOptions['revalidateBeforeDispatch']> {
  return () => {
    try {
      assertCurrent();
    } catch {
      throw new Error('RESTRICTED_PARTNER_REVOKED');
    }
    return null; // Keep the original resolved route and all existing provider/credential guards.
  };
}
