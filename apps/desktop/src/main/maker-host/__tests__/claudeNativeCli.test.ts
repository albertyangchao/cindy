/**
 * claude-native-cli —— 内置 Claude Code CLI 的登录态读取、登录拉起与代理 env。
 * CLI 子进程用假 child 代替;代理解析与 SOCKS 桥 mock 掉。
 */
import { EventEmitter } from 'node:events';
import {
  buildClaudeCliProxyEnv, CLAUDE_CLI_PROXY_CONTEXT_ENV, restoreInheritedClaudeCliProxyEnv,
} from '../claudeCliProxyEnvironment.js';

import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  binary: '/opt/cindy/claude' as string | null,
  envProxy: false,
  resolved: null as string | null,
  resolveError: null as Error | null,
  bridge: vi.fn(async () => 'http://127.0.0.1:5555'),
  spawn: vi.fn(),
  workers: [] as EventEmitter[],
}));

vi.mock('electron', () => ({ app: { isPackaged: true, getPath: () => '/tmp/cindy-test-user-data' } }));
vi.mock('@cindy/maker-core', () => ({ cleanProcessEnv: () => ({ PATH: '/usr/bin' }) }));
vi.mock('../../agent-binaries/index.js', () => ({ getReadyBinaryPath: () => h.binary }));
vi.mock('../../logger.js', () => ({
  createLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));
vi.mock('../outbound-proxy-resolver.js', () => ({
  resolveDesktopOutboundProxy: async () => {
    if (h.resolveError) throw h.resolveError;
    return h.resolved;
  },
}));
vi.mock('@cindy/anthropic-compat-proxy', async (original) => ({
  ...(await original<typeof import('@cindy/anthropic-compat-proxy')>()),
  hasProxyEnvConfig: () => h.envProxy,
}));
vi.mock('../claude-cli-proxy-bridge.js', () => ({ ensureClaudeCliProxyBridge: h.bridge }));
vi.mock('node:child_process', () => ({ spawn: h.spawn }));
vi.mock('node:worker_threads', () => ({
  Worker: class extends EventEmitter {
    constructor(_file: string, { workerData }: { workerData: { binary: string; env: NodeJS.ProcessEnv } }) {
      super();
      h.workers.push(this);
      // The worker transport is simulated; existing status/login cases still
      // drive the production client and observe the public authentication result.
      const child = h.spawn(workerData.binary, ['auth', 'status', '--json'], { env: workerData.env });
      let stdout = '';
      child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
      child.once('error', (error: Error) => this.emit('error', error));
      child.once('close', () => { this.emit('message', { stdout }); this.emit('exit', 0); });
    }
  },
}));

import {
  claudeCliNetworkEnv,
  parseClaudeCliLoginStatus,
  parseClaudeCliPlanUsageLine,
  peekClaudeCliLoginStatus,
  readClaudeCliPlanUsage,
  readClaudeCliLoginStatus,
  refreshClaudeCliLoginStatus,
  resetClaudeNativeCliForTest,
  runClaudeCliLogin,
} from '../claude-native-cli.js';

type FakeChild = EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; kill: ReturnType<typeof vi.fn> };

function fakeChild(result: { stdout?: string; code?: number; error?: Error } | 'hang'): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn(() => {
    setImmediate(() => child.emit('close', null));
    return true;
  });
  if (result !== 'hang') {
    setImmediate(() => {
      if (result.error) {
        child.emit('error', result.error);
        return;
      }
      if (result.stdout) child.stdout.emit('data', Buffer.from(result.stdout));
      child.emit('close', result.code ?? 0);
    });
  }
  return child;
}

const SUBSCRIPTION = JSON.stringify({
  loggedIn: true,
  authMethod: 'claude.ai',
  apiProvider: 'firstParty',
  email: 'user@example.com',
  subscriptionType: 'max',
});
const API_KEY_LOGIN = JSON.stringify({ loggedIn: true, authMethod: 'api_key', apiProvider: 'firstParty', apiKeySource: 'ANTHROPIC_API_KEY' });
const LOGGED_OUT = JSON.stringify({ loggedIn: false, authMethod: 'none', apiProvider: 'firstParty' });

function argsOf(call: unknown[]): string[] {
  return call[1] as string[];
}

beforeEach(() => {
  resetClaudeNativeCliForTest();
  h.binary = '/opt/cindy/claude';
  h.envProxy = false;
  h.resolved = null;
  h.resolveError = null;
  h.bridge.mockClear();
  h.bridge.mockImplementation(async () => 'http://127.0.0.1:5555');
  h.spawn.mockReset();
  h.workers.length = 0;
});

describe('parseClaudeCliLoginStatus', () => {
  it('isolates concurrent custom profiles without publishing them as the default CLI login', async () => {
    h.spawn.mockImplementation((_binary: string, _args: string[], options: { env: Record<string, string> }) =>
      fakeChild({ stdout: JSON.stringify({ loggedIn: true, authMethod: 'claude.ai', email: options.env.CLAUDE_CONFIG_DIR ?? 'default' }) }));
    const [a, b] = await Promise.all([
      refreshClaudeCliLoginStatus({ configDir: '/profiles/a' }),
      refreshClaudeCliLoginStatus({ configDir: '/profiles/b' }),
    ]);
    expect(a.email).toBe('/profiles/a');
    expect(b.email).toBe('/profiles/b');
    expect(peekClaudeCliLoginStatus()).toBeNull();
    await refreshClaudeCliLoginStatus();
    expect(peekClaudeCliLoginStatus()?.email).toBe('default');
    expect(h.spawn.mock.calls[2][2].env).not.toHaveProperty('CLAUDE_CONFIG_DIR');
  });
  it('只把 Claude.ai 订阅账号的 OAuth 登录当作 Claude 订阅', () => {
    expect(parseClaudeCliLoginStatus(SUBSCRIPTION)).toEqual({
      loggedIn: true,
      authMethod: 'claude.ai',
      subscriptionType: 'max',
      email: 'user@example.com',
    });
  });

  it.each([
    ['Console 账号(managed key)', { loggedIn: true, authMethod: 'claude.ai', apiProvider: 'firstParty', apiKeySource: '/login managed key' }],
    ['API Key', { loggedIn: true, authMethod: 'api_key', apiProvider: 'firstParty' }],
    ['apiKeyHelper', { loggedIn: true, authMethod: 'api_key_helper', apiProvider: 'firstParty' }],
    ['中转 token(ANTHROPIC_AUTH_TOKEN)', { loggedIn: true, authMethod: 'oauth_token', apiProvider: 'firstParty' }],
    ['第三方云', { loggedIn: true, authMethod: 'third_party', apiProvider: 'bedrock' }],
    ['订阅登录但指向第三方云', { loggedIn: true, authMethod: 'claude.ai', apiProvider: 'vertex' }],
  ])('%s → 已登录但不是订阅', (_label, payload) => {
    expect(parseClaudeCliLoginStatus(JSON.stringify(payload))).toEqual({ loggedIn: false, notSubscription: true });
  });

  it('未登录与异常输出', () => {
    expect(parseClaudeCliLoginStatus(LOGGED_OUT)).toEqual({ loggedIn: false });
    expect(parseClaudeCliLoginStatus('not json')).toBeNull();
    expect(parseClaudeCliLoginStatus('[]')).toBeNull();
    expect(parseClaudeCliLoginStatus('{"authMethod":"claude.ai"}')).toBeNull();
  });
});

describe('claudeCliNetworkEnv', () => {
  // Test value (unit): exercise the real CLI env builder and Desktop startup
  // restoration, protecting the 0.1.133 descendant-launch failure. Existing
  // cases only cover CLI traffic, not a replacement host inheriting its bridge.
  it('carries the parent proxy environment when a CLI descendant launches Cindy', async () => {
    const original = 'socks5://proxy.example.test:1080';
    vi.stubEnv('HTTPS_PROXY', original);
    // Windows aliases share one native environment entry.
    if (process.platform !== 'win32') vi.stubEnv('https_proxy', undefined);
    vi.stubEnv('NO_PROXY', '.example.test');
    try {
      h.envProxy = true;
      h.resolved = original;
      const childEnv = await claudeCliNetworkEnv();
      expect(process.env.HTTPS_PROXY).toBe(original);
      expect(process.env.https_proxy).toBe(process.platform === 'win32' ? original : undefined);
      expect(childEnv[CLAUDE_CLI_PROXY_CONTEXT_ENV]).toEqual(expect.any(String));
      const relaunched: NodeJS.ProcessEnv = {
        HTTPS_PROXY: original, NO_PROXY: '.example.test', ...childEnv,
      };
      restoreInheritedClaudeCliProxyEnv(relaunched);
      expect(relaunched.HTTPS_PROXY).toBe(original);
      expect(relaunched.https_proxy).toBe(process.platform === 'win32' ? original : undefined);
      expect(relaunched.NO_PROXY).toBe('.example.test');
      expect(relaunched[CLAUDE_CLI_PROXY_CONTEXT_ENV]).toBeUndefined();
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('retains the original route across multiple generations of CLI bridge environments', () => {
    const original = { HTTPS_PROXY: 'socks5://original.example.test:1080', NO_PROXY: '.original.test' };
    const first = { ...original, ...buildClaudeCliProxyEnv('http://127.0.0.1:5555', true, original) };
    const second = { ...first, ...buildClaudeCliProxyEnv('http://127.0.0.1:5556', true, first) };
    restoreInheritedClaudeCliProxyEnv(second);
    expect(second).toEqual(original);
    expect(first.HTTPS_PROXY).toBe('http://127.0.0.1:5555');
  });

  it('restores system proxy selection and original exclusions without mutating the parent', () => {
    const parent = { PATH: '/fixture/bin', NO_PROXY: '.internal.test', no_proxy: '' };
    const child = { ...parent, ...buildClaudeCliProxyEnv('http://127.0.0.1:5555', true, parent) };
    expect(parent).toEqual({ PATH: '/fixture/bin', NO_PROXY: '.internal.test', no_proxy: '' });
    restoreInheritedClaudeCliProxyEnv(child);
    expect(child).toEqual(parent);
    // Repeated startup normalization is harmless.
    restoreInheritedClaudeCliProxyEnv(child);
    expect(child).toEqual(parent);
  });

  it.each([
    ['https_proxy', 'http://explicit-proxy.example.test:8080', 'HTTPS_PROXY'],
    ['no_proxy', '.explicit.example.test', 'NO_PROXY'],
  ] as const)('keeps a downstream %s choice without reviving its shadowing alias', (key, choice, alias) => {
    const parent = { HTTPS_PROXY: 'socks5://parent.example.test:1080', NO_PROXY: '.parent.test' };
    const child: NodeJS.ProcessEnv = {
      ...parent,
      ...buildClaudeCliProxyEnv('http://127.0.0.1:5555', true, parent),
      [key]: choice,
    };
    restoreInheritedClaudeCliProxyEnv(child);
    expect(child[key]).toBe(choice);
    expect(child[alias]).toBeUndefined();
    expect(child[CLAUDE_CLI_PROXY_CONTEXT_ENV]).toBeUndefined();
  });

  it.each(['HTTPS_PROXY', 'https_proxy', 'Https_Proxy'])(
    'preserves a Windows parent using the %s spelling after native alias folding',
    (key) => {
      const original = 'socks5://windows-parent.example.test:1080';
      const parent = { [key]: original };
      const patch = buildClaudeCliProxyEnv('http://127.0.0.1:5555', false, parent, 'win32');
      // Windows forwards one key per case-insensitive name, sorted as Node's
      // spawn env serializer does. No host path/platform behavior is mocked.
      const child: NodeJS.ProcessEnv = {};
      const seen = new Set<string>();
      const merged = { ...parent, ...patch };
      for (const name of Object.keys(merged).sort()) {
        if (seen.has(name.toUpperCase())) continue;
        seen.add(name.toUpperCase());
        child[name] = merged[name];
      }
      restoreInheritedClaudeCliProxyEnv(child);
      expect(child.https_proxy ?? child.HTTPS_PROXY).toBe(original);
    },
  );

  it('preserves an unmarked user proxy even when it points at a retired loopback port', () => {
    const explicit = { HTTPS_PROXY: 'http://127.0.0.1:53627', NO_PROXY: '.internal.test' };
    const env = { ...explicit };
    restoreInheritedClaudeCliProxyEnv(env);
    expect(env).toEqual(explicit);
  });

  it.each([
    ['malformed JSON', '{'],
    ['future context', JSON.stringify({ version: 2, overrides: [] })],
    ['foreign env key', JSON.stringify({ version: 1, overrides: [
      { key: 'HTTPS_PROXY', injected: 'http://127.0.0.1:5555', previous: null },
      { key: 'PATH', injected: '/fixture/bin', previous: '/other' },
    ] })],
    ['non-bridge proxy', JSON.stringify({ version: 1, overrides: [
      { key: 'HTTPS_PROXY', injected: 'http://proxy.example.test:5555', previous: null },
      { key: 'https_proxy', injected: 'http://proxy.example.test:5555', previous: null },
    ] })],
  ])('leaves routing unchanged for %s metadata', (_label, context) => {
    const env: NodeJS.ProcessEnv = {
      HTTPS_PROXY: 'http://127.0.0.1:5555', PATH: '/fixture/bin',
      [CLAUDE_CLI_PROXY_CONTEXT_ENV]: context,
    };
    restoreInheritedClaudeCliProxyEnv(env);
    expect(env).toEqual({ HTTPS_PROXY: 'http://127.0.0.1:5555', PATH: '/fixture/bin' });
  });

  it('代理 env 已给出 HTTP 代理:不动,子进程直接继承', async () => {
    h.envProxy = true;
    h.resolved = 'http://127.0.0.1:7890';
    await expect(claudeCliNetworkEnv()).resolves.toEqual({});
    expect(h.bridge).not.toHaveBeenCalled();
  });

  it.each([
    ['HTTP', 'http://127.0.0.1:7890'],
    ['SOCKS5', 'socks5://127.0.0.1:7891'],
  ])('系统 %s 代理:HTTPS_PROXY 指向按目标解析出口的本机桥,不下发 HTTP_PROXY', async (_kind, proxy) => {
    h.resolved = proxy;
    await expect(claudeCliNetworkEnv()).resolves.toEqual({
      HTTPS_PROXY: 'http://127.0.0.1:5555',
      https_proxy: 'http://127.0.0.1:5555',
      [CLAUDE_CLI_PROXY_CONTEXT_ENV]: expect.any(String),
      NO_PROXY: 'localhost,127.0.0.1,::1',
      no_proxy: 'localhost,127.0.0.1,::1',
    });
    // 桥拿到的是逐目标解析器,而不是「对 api.anthropic.com 解析出的那一个代理」。
    expect(h.bridge).toHaveBeenCalledWith(expect.any(Function));
  });

  it('代理 env 只有 SOCKS5(如 ALL_PROXY):经桥覆盖 HTTPS_PROXY,保留用户自己的 NO_PROXY', async () => {
    h.envProxy = true;
    h.resolved = 'socks5://127.0.0.1:1080';
    await expect(claudeCliNetworkEnv()).resolves.toEqual({
      HTTPS_PROXY: 'http://127.0.0.1:5555',
      https_proxy: 'http://127.0.0.1:5555',
      [CLAUDE_CLI_PROXY_CONTEXT_ENV]: expect.any(String),
    });
  });

  it('直连、解析失败、桥起不来:都不下发', async () => {
    await expect(claudeCliNetworkEnv()).resolves.toEqual({});
    h.resolveError = new Error('resolver down');
    await expect(claudeCliNetworkEnv()).resolves.toEqual({});
    h.resolveError = null;
    h.resolved = 'socks5://127.0.0.1:7891';
    h.bridge.mockRejectedValueOnce(new Error('listen failed'));
    await expect(claudeCliNetworkEnv()).resolves.toEqual({});
  });
});

describe('登录态读取', () => {
  // KFJS unit regression: a worker dying before its response must release the
  // in-flight status query and keep the previous login result (no hung refresh).
  it('worker 提前退出时保留上次状态，force 可以重新查询', async () => {
    h.spawn.mockImplementationOnce(() => fakeChild({ stdout: SUBSCRIPTION }));
    await refreshClaudeCliLoginStatus();
    h.spawn.mockImplementationOnce(() => fakeChild('hang'));
    const pending = refreshClaudeCliLoginStatus({ force: true });
    await vi.waitFor(() => expect(h.workers).toHaveLength(2));
    h.workers[1]!.emit('exit', 1);
    await expect(pending).resolves.toMatchObject({ loggedIn: true });
    h.spawn.mockImplementationOnce(() => fakeChild({ stdout: LOGGED_OUT, code: 1 }));
    await expect(refreshClaudeCliLoginStatus({ force: true })).resolves.toMatchObject({ loggedIn: false });
  });
  it('读失败后退避,期间不再反复拉起 CLI;force 绕过退避', async () => {
    h.spawn.mockImplementation(() => fakeChild({ error: new Error('ENOENT') }));
    await expect(refreshClaudeCliLoginStatus()).resolves.toEqual({ loggedIn: false });
    await expect(refreshClaudeCliLoginStatus()).resolves.toEqual({ loggedIn: false });
    expect(h.spawn).toHaveBeenCalledTimes(1);
    h.spawn.mockImplementation(() => fakeChild({ stdout: SUBSCRIPTION }));
    await expect(refreshClaudeCliLoginStatus({ force: true })).resolves.toMatchObject({ loggedIn: true });
    expect(h.spawn).toHaveBeenCalledTimes(2);
    expect(argsOf(h.spawn.mock.calls[1])).toEqual(['auth', 'status', '--json']);
  });

  it('内置 CLI 尚未就绪不算失败:不进退避,就绪后下一次读取立即拉起', async () => {
    h.binary = null;
    await expect(refreshClaudeCliLoginStatus()).resolves.toEqual({ loggedIn: false });
    expect(h.spawn).not.toHaveBeenCalled();
    // 启动期二进制准备完成后的补读:不能被上一次「未就绪」挡在 30s 退避里。
    h.binary = '/opt/cindy/claude';
    h.spawn.mockImplementation(() => fakeChild({ stdout: SUBSCRIPTION }));
    await expect(readClaudeCliLoginStatus()).resolves.toMatchObject({ loggedIn: true });
    expect(h.spawn).toHaveBeenCalledTimes(1);
  });

  it('staleWhileRevalidate:没有缓存时不等 CLI,后台读完再更新缓存', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    h.spawn.mockImplementation(() => {
      const child = fakeChild('hang');
      void gate.then(() => {
        child.stdout.emit('data', Buffer.from(SUBSCRIPTION));
        child.emit('close', 0);
      });
      return child;
    });
    await expect(readClaudeCliLoginStatus({ maxAgeMs: 30_000, staleWhileRevalidate: true })).resolves.toEqual({
      loggedIn: false,
    });
    expect(h.spawn).toHaveBeenCalledTimes(1);
    release();
    await vi.waitFor(() => expect(peekClaudeCliLoginStatus()).toMatchObject({ loggedIn: true }));
    // 有新鲜缓存时直接返回,不再拉起。
    await expect(readClaudeCliLoginStatus({ maxAgeMs: 30_000, staleWhileRevalidate: true })).resolves.toMatchObject({
      loggedIn: true,
    });
    expect(h.spawn).toHaveBeenCalledTimes(1);
  });
});

describe('runClaudeCliLogin', () => {
  it('已登录直接返回,不拉起登录', async () => {
    h.spawn.mockImplementation(() => fakeChild({ stdout: SUBSCRIPTION }));
    await expect(runClaudeCliLogin(new AbortController().signal)).resolves.toMatchObject({ ok: true });
    expect(h.spawn).toHaveBeenCalledTimes(1);
  });

  it('CLI 用非订阅方式登录:返回 not_a_subscription,不替用户改 CLI 的登录', async () => {
    h.spawn.mockImplementation(() => fakeChild({ stdout: API_KEY_LOGIN }));
    await expect(runClaudeCliLogin(new AbortController().signal)).resolves.toEqual({
      ok: false,
      reason: 'not_a_subscription',
    });
    expect(h.spawn).toHaveBeenCalledTimes(1);
    expect(argsOf(h.spawn.mock.calls[0])).toEqual(['auth', 'status', '--json']);
  });

  it('拉起 `claude auth login --claudeai`,完成后以重读的登录态为结论', async () => {
    h.spawn
      .mockImplementationOnce(() => fakeChild({ stdout: LOGGED_OUT }))
      .mockImplementationOnce(() => fakeChild({ stdout: 'Login successful.', code: 0 }))
      .mockImplementationOnce(() => fakeChild({ stdout: SUBSCRIPTION }));
    await expect(runClaudeCliLogin(new AbortController().signal)).resolves.toMatchObject({
      ok: true,
      status: { loggedIn: true },
    });
    expect(argsOf(h.spawn.mock.calls[1])).toEqual(['auth', 'login', '--claudeai']);
  });

  it('取消时结束登录子进程', async () => {
    const login = fakeChild('hang');
    h.spawn
      .mockImplementationOnce(() => fakeChild({ stdout: LOGGED_OUT }))
      .mockImplementationOnce(() => login);
    const abort = new AbortController();
    const pending = runClaudeCliLogin(abort.signal);
    await vi.waitFor(() => expect(h.spawn).toHaveBeenCalledTimes(2));
    abort.abort();
    await expect(pending).resolves.toEqual({ ok: false, reason: 'login_cancelled' });
    expect(login.kill).toHaveBeenCalled();
  });

  it('内置 CLI 不可用 → local_unavailable', async () => {
    h.binary = null;
    await expect(runClaudeCliLogin(new AbortController().signal)).resolves.toEqual({
      ok: false,
      reason: 'local_unavailable',
    });
    expect(h.spawn).not.toHaveBeenCalled();
  });
});

type FakeSdkChild = FakeChild & { stdin: EventEmitter & { write: ReturnType<typeof vi.fn> } };

/** SDK 模式的假 CLI:收到 get_usage 请求后按 reply 回一行(reply 为 null 时不回)。 */
function fakeSdkChild(reply: (requestId: string) => unknown): FakeSdkChild {
  const child = fakeChild('hang') as FakeSdkChild;
  const stdin = new EventEmitter() as FakeSdkChild['stdin'];
  stdin.write = vi.fn((line: string) => {
    const message = JSON.parse(line) as { request_id: string; request: { subtype: string } };
    if (message.request.subtype !== 'get_usage') return true;
    const response = reply(message.request_id);
    if (response !== null) {
      setImmediate(() => {
        child.stdout.emit('data', Buffer.from(`{"type":"system","subtype":"init"}\n${JSON.stringify(response)}\n`));
      });
    }
    return true;
  });
  child.stdin = stdin;
  return child;
}

const RATE_LIMITS = { limits: [{ kind: 'session', percent: 5, resets_at: '2026-09-26T04:00:00Z' }] };

describe('readClaudeCliPlanUsage', () => {
  it('发 get_usage 控制请求,取 rate_limits 后结束 CLI;拉起时隔离项目设置 / MCP / 会话记录', async () => {
    const child = fakeSdkChild((id) => ({
      type: 'control_response',
      response: {
        subtype: 'success',
        request_id: id,
        response: { subscription_type: 'max', rate_limits_available: true, rate_limits: RATE_LIMITS },
      },
    }));
    h.spawn.mockReturnValue(child);
    await expect(readClaudeCliPlanUsage()).resolves.toEqual({ rateLimits: RATE_LIMITS, subscriptionType: 'max' });
    const args = argsOf(h.spawn.mock.calls[0]!);
    expect(args).toEqual(expect.arrayContaining([
      '--input-format', 'stream-json', '--no-session-persistence', '--strict-mcp-config', '--setting-sources', 'user',
    ]));
    const request = JSON.parse(child.stdin.write.mock.calls[1]![0] as string);
    expect(request.request).toEqual({ subtype: 'get_usage', skip_behaviors: true });
    expect(child.kill).toHaveBeenCalled();
  });

  it('账号没有套餐余量 → null;控制请求报错 / CLI 提前退出 → 抛错', async () => {
    h.spawn.mockReturnValueOnce(fakeSdkChild((id) => ({
      type: 'control_response',
      response: { subtype: 'success', request_id: id, response: { rate_limits_available: false, rate_limits: null } },
    })));
    await expect(readClaudeCliPlanUsage()).resolves.toBeNull();

    h.spawn.mockReturnValueOnce(fakeSdkChild((id) => ({
      type: 'control_response',
      response: { subtype: 'error', request_id: id, error: 'get_usage is not supported in this context' },
    })));
    await expect(readClaudeCliPlanUsage()).rejects.toThrow('not supported');

    const exiting = fakeSdkChild(() => null);
    h.spawn.mockReturnValueOnce(exiting);
    const pending = readClaudeCliPlanUsage();
    setImmediate(() => exiting.emit('close', 1));
    await expect(pending).rejects.toThrow('exited');
  });

  it('内置 CLI 不可用时不拉起进程', async () => {
    h.binary = null;
    await expect(readClaudeCliPlanUsage()).rejects.toThrow('unavailable');
    expect(h.spawn).not.toHaveBeenCalled();
  });
});

describe('parseClaudeCliPlanUsageLine', () => {
  it('忽略非本请求的行与无法解析的行', () => {
    expect(parseClaudeCliPlanUsageLine('not json')).toBeNull();
    expect(parseClaudeCliPlanUsageLine('{"type":"system"}')).toBeNull();
    expect(parseClaudeCliPlanUsageLine(JSON.stringify({
      type: 'control_response',
      response: { subtype: 'success', request_id: 'cindy-init', response: {} },
    }))).toBeNull();
  });

  it('只有 rate_limits_available=false 才算没有余量;缺 rate_limits 按形状变化报错', () => {
    const line = (response: unknown) => JSON.stringify({
      type: 'control_response',
      response: { subtype: 'success', request_id: 'cindy-plan-usage', response },
    });
    expect(parseClaudeCliPlanUsageLine(line({ rate_limits_available: false }))).toEqual({ usage: null });
    expect(parseClaudeCliPlanUsageLine(line({ rate_limits_available: true }))?.error).toMatch('no rate_limits');
    expect(parseClaudeCliPlanUsageLine(line({}))?.error).toMatch('no rate_limits');
  });
});
