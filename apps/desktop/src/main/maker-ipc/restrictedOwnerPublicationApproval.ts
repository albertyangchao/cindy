import type { BrowserWindow, MessageBoxOptions, MessageBoxReturnValue } from 'electron';
import type { OwnerPublicationIdentityInput } from './restrictedOwnerPublication.js';

/** A native, trusted-window identity decision; plugin settings and model text cannot answer it. */
export async function approveOwnerPublicationIdentity(input: OwnerPublicationIdentityInput, ports: {
  window(): BrowserWindow | null | undefined;
  trusted(window: BrowserWindow): boolean;
  show(window: BrowserWindow, options: MessageBoxOptions): Promise<MessageBoxReturnValue>;
  text(key: string): string;
}) {
  input.assertCurrent();
  const window = ports.window();
  if (!window || window.isDestroyed() || !ports.trusted(window) ||
      !['register', 'revoke'].includes(input.action) || !input.routes.length ||
      !/^[a-f0-9]{64}$/.test(input.runtimeIdentity)) throw Error('OWNER_PUBLICATION_DENIED');
  const t = (key: string) => ports.text('restrictedOwnerPublication.' + key);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const answer = await Promise.race([
      ports.show(window, {
        type: 'warning',
        title: t(input.action === 'register' ? 'registerTitle' : 'revokeTitle'),
        message: t(input.action === 'register' ? 'registerMessage' : 'revokeMessage'),
        detail: t('scope') + '\n\n' + input.sourceText.slice(0, 4000) + '\n\n' +
          JSON.stringify({ domainId: input.domainId, principalId: input.channelPrincipalId,
            partnerId: input.partnerId, routes: input.routes, runId: input.sourceRunId,
            publicOrigin: input.publicOrigin, sourceRoot: input.sourceRoot,
            runtimeIdentity: input.runtimeIdentity }, null, 2),
        ...(input.action === 'register' ? { checkboxLabel: t('identityCheckbox'), checkboxChecked: false } : {}),
        buttons: [ports.text('common.cancel'), t(input.action === 'register' ? 'registerButton' : 'revokeButton')],
        defaultId: 0,
        cancelId: 0,
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Error('OWNER_PUBLICATION_DENIED')), 30000);
      }),
    ]);
    input.assertCurrent();
    if (window.isDestroyed() || !ports.trusted(window)) throw Error('OWNER_PUBLICATION_DENIED');
    return answer.response === 1 && (input.action === 'revoke' || answer.checkboxChecked === true);
  } finally { if (timer) clearTimeout(timer); }
}
