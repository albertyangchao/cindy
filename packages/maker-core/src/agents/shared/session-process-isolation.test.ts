import { describe, expect, it } from 'vitest';
import { isolatedLocalLaunch, localModelProxyEndpoints, projectModelRequestParameters } from './session-process-isolation.js';

describe('one-process host restriction', () => {
  it.each(['codex', 'pi', 'claude'])('preserves the existing %s launch when no restriction is supplied', (command) => {
    const args = ['native', 'argument'];
    const launch = isolatedLocalLaunch(command, args, undefined, undefined, 'win32');
    expect(launch).toEqual({ command, args });
    launch.args.push('only-this-launch');
    expect(args).toEqual(['native', 'argument']);
  });

  it('binds the wrapper to the exact cwd and leaves argv boundaries intact', () => {
    const profile = '(version 1)(allow default)';
    expect(isolatedLocalLaunch('/tool', ['space value', '$()'], '/work', {
      workingDirectory: '/work', seatbeltProfile: profile,
    }, 'darwin')).toEqual({ command: '/usr/bin/sandbox-exec', args: ['-p', profile, '/tool', 'space value', '$()'] });
  });

  it.each(['linux', 'win32'])('fails closed on unsupported %s instead of removing the restriction', (platform) => {
    expect(() => isolatedLocalLaunch('/tool', [], '/work', {
      workingDirectory: '/work', seatbeltProfile: '(version 1)',
    }, platform)).toThrow('SESSION_PROCESS_ISOLATION_UNSUPPORTED');
  });

  it.each([undefined, 'relative', '/other'])('rejects a mismatched or missing cwd (%s)', (cwd) => {
    expect(() => isolatedLocalLaunch('/tool', [], cwd, {
      workingDirectory: '/work', seatbeltProfile: '(version 1)',
    }, 'darwin')).toThrow('SESSION_PROCESS_ISOLATION_DIRECTORY_MISMATCH');
  });

  it.each(['', '  ', '\0'])('rejects an invalid profile before any spawn (%j)', (seatbeltProfile) => {
    expect(() => isolatedLocalLaunch('/tool', [], '/work', {
      workingDirectory: '/work', seatbeltProfile,
    }, 'darwin')).toThrow('SESSION_PROCESS_ISOLATION_INVALID_PROFILE');
  });
});

describe('outbound parameter projection', () => {
  it('only projects model/effort/service tier from the final payload', () => {
    const body = { model: 'gpt-6.1-sol', reasoning: { effort: 'high' }, service_tier: 'default' };
    Object.defineProperty(body, 'headers', { get() { throw new Error('must not inspect headers'); } });
    Object.defineProperty(body, 'input', { get() { throw new Error('must not inspect prompt'); } });
    expect(projectModelRequestParameters(body, 'gpt-6.1-sol')).toEqual({ model: 'gpt-6.1-sol', effort: 'high', serviceTier: 'default' });
  });

  it.each([null, [], {}, { model: 'unapproved', reasoning: { effort: 'unapproved' }, service_tier: 'unapproved' }])('preserves missing or unapproved values as UNKNOWN (%j)', (body) => {
    expect(projectModelRequestParameters(body, 'gpt-6.1-sol')).toEqual({ model: 'UNKNOWN', effort: 'UNKNOWN', serviceTier: 'UNKNOWN' });
  });
});

describe('existing native model bridge metadata', () => {
  it('extracts only unique loopback origins from base URL overrides', () => {
    expect(localModelProxyEndpoints(['-c', 'model_providers.cindy_openai.base_url="http://127.0.0.1:1234/v1"',
      'model_providers.cindy_openai.base_url=http://127.0.0.1:1234/responses',
      'model_providers.other.http_headers={}', 'unrelated=/private'])).toEqual(['http://127.0.0.1:1234']);
  });
  it.each(['https://127.0.0.1:1234', 'http://external.invalid:1234', 'http://user:password@127.0.0.1:1234', 'not-a-url'])('refuses %s rather than dropping constraints', url => {
    expect(localModelProxyEndpoints([`model_providers.cindy_openai.base_url=${JSON.stringify(url)}`])).toEqual([]);
  });
});
