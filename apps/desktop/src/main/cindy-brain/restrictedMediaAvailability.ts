import type { MediaKind } from './restrictedMediaAdapter.js';

type MediaRoutes = Readonly<Partial<Record<MediaKind, Readonly<{
  providerId: string;
  modelId: string;
  voice?: string;
}>>>>;

export type RestrictedMediaAvailability = Readonly<Record<MediaKind, Readonly<{
  state: 'READY' | 'NOT_CONFIGURED' | 'NOT_AUTHORIZED' | 'REAPPROVAL_REQUIRED';
}>>>;

/** Read-only status, never an authorization or a fallback provider selection.
 * A missing route can be explained without dispatching an effect. A replacement
 * route still needs the original owner approval and must not run on that grant.
 */
export function restrictedMediaAvailability(
  approved: MediaRoutes,
  configured: MediaRoutes,
): RestrictedMediaAvailability {
  const result = {} as Record<MediaKind, { state: RestrictedMediaAvailability[MediaKind]['state'] }>;
  for (const kind of ['vision', 'draw', 'edit', 'stt', 'tts'] as const) {
    const state = !approved[kind]
      ? 'NOT_AUTHORIZED'
      : !configured[kind]
        ? 'NOT_CONFIGURED'
        : JSON.stringify(approved[kind]) === JSON.stringify(configured[kind])
          ? 'READY'
          : 'REAPPROVAL_REQUIRED';
    result[kind] = Object.freeze({ state });
  }
  return Object.freeze(result);
}

/** Safe tool result used only after Main has checked the current subject grant,
 * the request shape and ownership of any input. No provider diagnostics escape.
 */
export function restrictedMediaNotConfigured(kind: MediaKind) {
  const labels: Record<MediaKind, string> = {
    vision: '图片理解',
    draw: '绘图',
    edit: '改图',
    stt: '语音转写',
    tts: '语音回复',
  };
  return {
    success: false as const,
    contentItems: [{
      type: 'inputText' as const,
      text: JSON.stringify({
        state: 'NOT_CONFIGURED',
        kind,
        message: `${labels[kind]}服务未配置或当前不可用；请主人检查现有服务设置。本次没有调用该媒体服务。`,
      }),
    }],
  };
}
