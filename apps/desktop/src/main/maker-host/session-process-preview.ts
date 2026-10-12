/** Explicit development-only experiment. No installed-client or global setting writes. */
import { app } from 'electron';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { projectModelRequestParameters, type AgentDeps, type SessionProcessIsolation } from '@cindy/maker-core';
import type { Maker } from '@cindy/maker-core';

interface PreviewDescriptor {
  workingDirectory: string;
  runtimeDirectory: string;
  seatbeltProfile: string;
  evidenceFile: string;
  expectedModel: string;
  startupEvidenceFile?: string;
  experiment?: { agentKind: 'pi' | 'claude-code' | 'codex'; prompt: string; resultFile: string };
}

let previewRunStarted = false;
/** Trusted developer task, using the ordinary Maker/auth/approval path. No IPC. */
export async function runSessionProcessPreview(maker: Maker): Promise<void> {
  const value = descriptor();
  const experiment = value?.experiment;
  if (!value || !experiment) return;
  if (previewRunStarted) return;
  if (!['pi', 'claude-code', 'codex'].includes(experiment.agentKind)
      || !path.isAbsolute(experiment.resultFile) || !experiment.prompt.trim()) {
    throw new Error('SESSION_PREVIEW_INVALID_EXPERIMENT');
  }
  const started = Date.now();
  if (existsSync(experiment.resultFile)) throw new Error('SESSION_PREVIEW_RESULT_ALREADY_EXISTS');
  previewRunStarted = true;
  const counts: Record<string, number> = {};
  const probes: string[] = [];
  const signals: string[] = [];
  const result: Record<string, unknown> = { phase: 'restricted-development-preview',
    agentKind: experiment.agentKind, pid: process.pid, startedAt: new Date(started).toISOString(),
    model: 'gpt-6.1-sol', effort: 'high', fastMode: false, responseModel: 'UNKNOWN',
    tokens: 'UNKNOWN', timedOut: false, completed: false };
  let session: Awaited<ReturnType<Maker['createSession']>> | undefined;
  const write = () => writeFileSync(experiment.resultFile, JSON.stringify({ ...result,
    elapsedSeconds: (Date.now() - started) / 1000, counts, probes, signals }, null, 2) + '\n');
  // A marker/code whitelist, never a dump of model payloads, headers or credentials.
  const observe = (payload: unknown, toolResult = false) => {
    const text = JSON.stringify(payload) ?? '';
    if (toolResult && payload && typeof payload === 'object') {
      const data = payload as Record<string, unknown>;
      for (const field of ['fullText', 'text', 'output']) {
        if (typeof data[field] === 'string') {
          for (const match of data[field].matchAll(/^SOL_PROBE_[A-Z_]+=(?:DENIED|ALLOWED|FAIL|UNKNOWN)$/gm)) probes.push(match[0]);
        }
      }
    }
    for (const code of ['Operation not permitted', 'Permission denied', 'Auto-review denied',
      'Selected model is at capacity', 'SESSION_PROCESS_ISOLATION', 'SESSION_PREVIEW_', 'not authenticated']) {
      if (text.includes(code) && !signals.includes(code)) signals.push(code);
    }
  };
  write();
  try {
    session = await maker.createSession({ agentKind: experiment.agentKind,
      workingDir: value.workingDirectory, providerId: 'openai',
      model: experiment.agentKind === 'codex' ? value.expectedModel : `chatgpt/${value.expectedModel}`,
      effort: 'high', fastMode: false, permissionMode: 'auto', makerMemoryEnabled: false,
      botRuntimeProfile: { botId: 'sol-harness-benchmark-20261011', profileVersion: 1,
        skillPolicy: { mode: 'allowlist', configured: [], catalog: [] },
        mcpPolicy: { mode: 'allowlist', configured: [], catalog: [] },
        toolsetPolicy: { mode: 'allowlist', configured: [], catalog: [] } } });
    result.sessionId = session.id;
    await new Promise<void>((resolve, reject) => {
      let unsubscribe = () => {};
      const timeout = setTimeout(() => { result.timedOut = true; unsubscribe(); resolve(); }, Math.max(0, 1_200_000 - (Date.now() - started)));
      unsubscribe = session!.onEvent(event => {
        counts[event.type] = (counts[event.type] ?? 0) + 1;
        observe(event.data, event.type === 'tool_result' || event.type === 'tool_result_full');
        write();
        if (event.type === 'done' || (event.type === 'error'
            && (event.data as { isTerminal?: boolean; willRetry?: boolean }).isTerminal !== false
            && !(event.data as { willRetry?: boolean }).willRetry)) {
          result.completed = event.type === 'done';
          clearTimeout(timeout); unsubscribe(); resolve();
        }
      });
      void session!.send(experiment.prompt, { resolveAutoReviewUserIntent: async () => ({
        earlierUserMessages: ['那现在就开始吧，测完给一个完整的报告。允许参试修改其独立题目工作区源码并运行本地测试；不允许额外目录写入。'],
        currentUserMessage: experiment.prompt,
      }) }).then(sent => {
        if (!sent.accepted) { result.dispatch = sent; clearTimeout(timeout); unsubscribe(); resolve(); }
      }).catch(error => { clearTimeout(timeout); unsubscribe(); reject(error); });
    });
  } catch (error) {
    observe({ message: error instanceof Error ? error.message : String(error) });
    result.errorClass = error instanceof Error ? error.name : 'UNKNOWN';
  } finally {
    try { if (session) await maker.closeSession(session.id); }
    finally { write(); }
  }
}
let cached: PreviewDescriptor | undefined;

export function recordSessionProcessPreviewStage(stage: 'app-ready' | 'endpoints-ready' | 'model-access-ready'
    | 'update-recovery-ready' | 'dock-icon-ready' | 'presence-ready' | 'skills-ready'): void {
  const value = descriptor();
  if (!value?.startupEvidenceFile || !path.isAbsolute(value.startupEvidenceFile)) return;
  appendFileSync(value.startupEvidenceFile, JSON.stringify({ timestamp: new Date().toISOString(), stage, pid: process.pid }) + '\n');
}

function descriptor(): PreviewDescriptor | undefined {
  const file = process.env.XDT_SESSION_PROCESS_PREVIEW;
  if (!file) return undefined;
  if (app.isPackaged || process.env.XDT_ISOLATED !== '1') throw new Error('SESSION_PREVIEW_REQUIRES_ISOLATED_DEVELOPMENT');
  if (cached) return cached;
  const value: PreviewDescriptor = JSON.parse(readFileSync(file, 'utf8'));
  if (!path.isAbsolute(file) || !path.isAbsolute(value.workingDirectory)
      || !path.isAbsolute(value.runtimeDirectory) || !path.isAbsolute(value.evidenceFile)
      || typeof value.seatbeltProfile !== 'string' || !value.seatbeltProfile.trim()
      || value.expectedModel !== 'gpt-6.1-sol') throw new Error('SESSION_PREVIEW_INVALID_DESCRIPTOR');
  const relative = path.relative(value.runtimeDirectory, file);
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    throw new Error('SESSION_PREVIEW_DESCRIPTOR_MUST_BE_OUTSIDE_NATIVE_RUNTIME');
  }
  cached = Object.freeze(value);
  return cached;
}

function loopbackPorts(endpoints: readonly string[]): number[] {
  const ports: number[] = [];
  for (const endpoint of endpoints) {
    const url = new URL(endpoint);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || !url.port) {
      throw new Error('SESSION_PREVIEW_REQUIRES_EXISTING_LOOPBACK_MODEL_BRIDGE');
    }
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SESSION_PREVIEW_INVALID_BRIDGE_PORT');
    ports.push(port);
  }
  if (!ports.length) throw new Error('SESSION_PREVIEW_MODEL_BRIDGE_METADATA_MISSING');
  return [...new Set(ports)];
}

function piEndpoints(configDirectory: string | undefined, runtime: string): string[] {
  if (!configDirectory) throw new Error('SESSION_PREVIEW_PI_CONFIG_METADATA_MISSING');
  const relative = path.relative(runtime, configDirectory);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('SESSION_PREVIEW_PI_CONFIG_OUTSIDE_RUNTIME');
  const config = JSON.parse(readFileSync(path.join(configDirectory, 'models.json'), 'utf8'));
  // Native model metadata only. apiKey/header fields are never inspected or copied.
  const endpoints: string[] = [];
  for (const provider of Object.values(config.providers ?? {}) as Array<{ baseUrl?: unknown }>) {
    if (typeof provider.baseUrl === 'string') endpoints.push(provider.baseUrl);
  }
  return endpoints;
}

export const resolveSessionProcessPreview: NonNullable<AgentDeps['resolveLocalProcessIsolation']> = async (input) => {
  const value = descriptor();
  if (!value) return undefined;
  if (path.resolve(input.workingDirectory) !== path.resolve(value.workingDirectory)) throw new Error('SESSION_PREVIEW_WORKSPACE_MISMATCH');
  const isolation: SessionProcessIsolation = { workingDirectory: value.workingDirectory,
    runtimeDirectory: value.runtimeDirectory, seatbeltProfile: value.seatbeltProfile };
  if (input.phase === 'identity') return isolation; // Pool key only; no process starts here.
  const ports = loopbackPorts(input.kind === 'pi'
    ? piEndpoints(input.nativeConfigDirectory, value.runtimeDirectory) : input.networkEndpoints ?? []);
  // All descendants retain the exact model-bridge-only network restriction.
  // Native authentication still belongs to the existing host bridge.
  const exceptions = ports.map((port) => `(require-not (remote ip "localhost:${port}"))`).join(' ');
  return { ...isolation, seatbeltProfile: `${isolation.seatbeltProfile}\n(deny network-outbound (require-all ${exceptions}))` };
};

/** Final serialized body/frame, immediately before the existing sender. Never headers. */
export function recordSessionPreviewModelParameters(payload: unknown): void {
  const value = descriptor();
  if (!value) return;
  try {
    const parsed = Buffer.isBuffer(payload) ? JSON.parse(payload.toString('utf8'))
      : typeof payload === 'string' ? JSON.parse(payload) : payload;
    if (parsed === null || typeof parsed !== 'object' || !('model' in parsed)) return;
    const parameters = projectModelRequestParameters(parsed, value.expectedModel);
    appendFileSync(value.evidenceFile, JSON.stringify({ timestamp: new Date().toISOString(),
      ...parameters, responseModel: 'UNKNOWN', evidenceKind: 'existing-final-outbound-body' }) + '\n');
  } catch {
    // An unavailable projection is not replaced with config evidence; forwarding is unchanged.
  }
}
