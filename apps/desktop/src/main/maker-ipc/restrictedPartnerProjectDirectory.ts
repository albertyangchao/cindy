import type { MessageBoxOptions } from 'electron';

/** Native owner confirmation for an already canonical, existing project directory.
 * The directory path is displayed only in the trusted Host UI, never returned on wire.
 */
export async function confirmRestrictedPartnerProjectDirectory(
  input: { projectDir: string; principalId: string; label: string; assertCurrent(): void },
  t: (key: string) => string,
  show: (options: MessageBoxOptions) => Promise<{ response: number }>,
) {
  const result = await show({
    type: 'question',
    title: t('restrictedPartner.projectTitle'),
    message: t('restrictedPartner.projectMessage').replace('{{partner}}', input.label),
    detail: t('restrictedPartner.projectDetail')
      .replace('{{principal}}', input.principalId)
      .replace('{{directory}}', input.projectDir),
    buttons: [t('restrictedPartner.projectAllow'), t('restrictedPartner.projectCancel')],
    defaultId: 1,
    cancelId: 1,
  });
  input.assertCurrent();
  return result.response === 0
    ? { approved: true, paths: [input.projectDir], coverage: { workspace: [input.projectDir] } }
    : { approved: false, paths: [] };
}
