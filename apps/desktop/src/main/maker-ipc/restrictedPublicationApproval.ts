import { createHash } from 'node:crypto';
import type { BrowserWindow, MessageBoxOptions, MessageBoxReturnValue } from 'electron';
import type { NativePublicationOwnerInput } from './restrictedPartnerPublication.js';
/** Protected native owner consent, not a caller-supplied disclosure flag. */
export async function approveNativePublicRelease(
  input: NativePublicationOwnerInput,
  ports: {
    window(): BrowserWindow | null | undefined;
    trusted(w: BrowserWindow): boolean;
    show(w: BrowserWindow, o: MessageBoxOptions): Promise<MessageBoxReturnValue>;
  },
) {
  input.assertCurrent();
  const win = ports.window();
  if (
    !win ||
    win.isDestroyed() ||
    !ports.trusted(win) ||
    input.target !== 'canonical-public-report' ||
    input.disclosure !== 'PUBLIC_RELEASE' ||
    createHash('sha256').update(input.output).digest('hex') !== input.outputSha256
  )
    throw Error('NATIVE_PUBLIC_RELEASE_DENIED');
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const answer = await Promise.race([
      ports.show(win, {
        type: 'warning',
        title: 'PUBLIC_RELEASE — publish this exact completed reply',
        message:
          'Publish this reviewed, non-personal output to the public canonical report target?',
        detail:
          'Public target: ' +
          input.publicOrigin +
          '\nCompleted output SHA-256: ' +
          input.outputSha256 +
          '\nPartner: ' +
          input.partnerId +
          '\nPrincipal: ' +
          input.principalId +
          '\n\n' +
          input.output +
          (input.artifact
            ? '\n\nFinal stamped artifact SHA-256: ' +
              input.artifact.sha256 +
              '\nPublisher metadata binding SHA-256: ' +
              input.artifact.publisherBindingSha256 +
              '\nReviewed renderer identity: ' +
              input.runtimeIdentity
            : ''),
        checkboxLabel:
          'I reviewed this exact output. It contains no private or child-personal material. I approve PUBLIC_RELEASE only.',
        checkboxChecked: false,
        buttons: ['Cancel', 'Approve exact public release'],
        defaultId: 0,
        cancelId: 0,
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Error('NATIVE_PUBLIC_RELEASE_DENIED')), 30000);
      }),
    ]);
    input.assertCurrent();
    if (win.isDestroyed() || !ports.trusted(win)) throw Error('NATIVE_PUBLIC_RELEASE_DENIED');
    return {
      approved: answer.response === 1,
      publicNonPersonal: answer.response === 1 && answer.checkboxChecked === true,
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
