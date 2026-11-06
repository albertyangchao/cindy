import { getCurrentDbClientSnapshot } from '../localDb/client/current.js';

/** Invalidate restricted inputs before a profile write's first await. No ordinary-task policy change. */
export function createPartnerEpochs(owner: () => object | null) {
  const all = new WeakMap<object, Map<string, { revision: number; pending: number }>>();
  const state = (scope: object, id: string) => {
    let entries = all.get(scope);
    if (!entries) {
      entries = new Map();
      all.set(scope, entries);
    }
    let value = entries.get(id);
    if (!value) {
      value = { revision: 0, pending: 0 };
      entries.set(id, value);
    }
    return value;
  };
  return {
    capture(id: string) {
      const scope = owner();
      if (!scope) throw Error('RESTRICTED_PARTNER_REVOKED');
      const value = state(scope, id),
        revision = value.revision;
      const check = () => {
        if (owner() !== scope || value.pending || value.revision !== revision)
          throw Error('RESTRICTED_PARTNER_REVOKED');
      };
      check();
      return check;
    },
    async change<T>(id: string, operation: () => Promise<T>): Promise<T> {
      const scope = owner();
      if (!scope) return operation();
      const value = state(scope, id);
      value.revision++;
      value.pending++;
      try {
        return await operation();
      } finally {
        value.pending--;
      }
    },
  };
}
const epochs = createPartnerEpochs(getCurrentDbClientSnapshot);
export const captureRestrictedPartnerEpoch = epochs.capture;
export const withRestrictedPartnerChange = epochs.change;
