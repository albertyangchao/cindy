/** Actual Main native owner dialog authority. Never exported over IPC/Node/model arguments. */
import { createHash } from 'node:crypto';
import type { BrowserWindow, MessageBoxOptions, MessageBoxReturnValue } from 'electron';
import type { RestrictedPartnerGrant } from './restrictedPartnerExecution.js';
import type { MediaPermit } from '../cindy-brain/restrictedMediaAdapter.js';
import type { MediaUrlGrant, MediaUrlRole } from '../cindy-brain/restrictedMediaUrl.js';
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
export function nativeImageUrlAuthority(
  g: RestrictedPartnerGrant,
  current: () => void,
  ports: {
    window(): BrowserWindow | null | undefined;
    trusted(w: BrowserWindow): boolean;
    show(w: BrowserWindow, options: MessageBoxOptions): Promise<MessageBoxReturnValue>;
  },
) {
  const approved = new Map<string, MediaUrlGrant>();
  const key = (p: MediaPermit, url: string, role: MediaUrlRole) =>
    sha(JSON.stringify([p.binding, url, role]));
  return {
    approve: async (p: MediaPermit, raw: string, role: MediaUrlRole) => {
      current();
      p.assertCurrent();
      if (!['input', 'output'].includes(role) || typeof raw !== 'string' || raw.length > 8192)
        throw Error('RESTRICTED_MEDIA_URL_DENIED');
      let u: URL;
      try {
        u = new URL(raw);
      } catch {
        throw Error('RESTRICTED_MEDIA_URL_DENIED');
      }
      if (
        u.protocol !== 'https:' ||
        u.username ||
        u.password ||
        u.hash ||
        !u.hostname.includes('.') ||
        /[\[\]:]/.test(u.hostname) ||
        /^\d+(\.\d+){3}$/.test(u.hostname) ||
        u.hostname.endsWith('.') ||
        (u.port && u.port !== '443')
      )
        throw Error('RESTRICTED_MEDIA_URL_DENIED');
      const k = key(p, raw, role);
      if (approved.has(k)) return;
      const win = ports.window();
      if (!win || win.isDestroyed() || !ports.trusted(win))
        throw Error('RESTRICTED_MEDIA_URL_DENIED');
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const answer = await Promise.race([
          ports.show(win, {
            type: 'warning',
            title: role === 'input' ? 'Approve incoming image URL' : 'Restricted image download',
            message:
              role === 'input'
                ? 'Download this original message image for this partner?'
                : 'Download this generated image from the exact provider host?',
            detail:
              'Host: ' +
              u.hostname +
              '\nURL digest: ' +
              sha(raw) +
              '\nPartner: ' +
              g.partnerId +
              '\nPrincipal: ' +
              g.principalId +
              '\nEvent digest: ' +
              sha(p.binding.eventId) +
              '\nPurpose: ' +
              role +
              '\nThis approves one bounded download only. It does not approve another event, subject, output URL or retry. Unknown results are never resubmitted.',
            buttons: ['Cancel', 'Approve download'],
            defaultId: 0,
            cancelId: 0,
          }),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(Error('RESTRICTED_MEDIA_URL_DENIED')), 30000);
          }),
        ]);
        current();
        p.assertCurrent();
        if (win.isDestroyed() || !ports.trusted(win) || answer.response !== 1)
          throw Error('RESTRICTED_MEDIA_URL_DENIED');
        approved.set(k, {
          binding: { ...p.binding },
          role,
          sourceSha256: sha(raw),
          hosts: [u.hostname],
          revision: g.revision,
        });
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
    authorize: (p: MediaPermit, url: string, role: MediaUrlRole) => {
      current();
      p.assertCurrent();
      const a = approved.get(key(p, url, role));
      if (!a) throw Error('RESTRICTED_MEDIA_URL_DENIED');
      return a;
    },
    assertCurrent: (p: MediaPermit, a: MediaUrlGrant) => {
      current();
      p.assertCurrent();
      if (![...approved.values()].some((v) => JSON.stringify(v) === JSON.stringify(a)))
        throw Error('RESTRICTED_MEDIA_URL_DENIED');
    },
  };
}
