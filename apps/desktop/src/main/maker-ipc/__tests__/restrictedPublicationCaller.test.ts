import { afterEach, expect, it, vi } from 'vitest';
import {
  readRestrictedPublicationLaunchPolicy,
  restrictedPublicationLaunchEnvironment,
} from '../restrictedPublicationLaunch.js';
import {
  canonicalSidecar,
  publicMarker,
  releasePair,
  orderedPair,
  parseNativeFrame,
  digest,
} from '../restrictedPublicationProtocol.js';
import {
  controlledPublicationRuntime,
  createControlledPublicationAssembly,
  resolveControlledPublicationRoot,
  supportedPublicationRoot,
} from '../restrictedPublicationCaller.js';
afterEach(() => vi.unstubAllEnvs());
it('canonical protocol preserves exact Unicode content, validates both members before fixed tuple conversion and rejects duplicate JSON', () => {
  const b = {
    nativeActionId: 'synthetic',
    artifactRelative: 'core/imessage/imessage-' + 'e'.repeat(32) + '.html',
    artifactSha256: 'a'.repeat(64),
    publisherBindingSha256: 'b'.repeat(64),
    completedOutputSha256: digest('合成正文'),
    generation: 'synthetic-generation',
  };
  const pair = releasePair(b);
  expect(
    orderedPair(Object.fromEntries(Object.entries(pair).reverse()), b).map(([name]) => name),
  ).toEqual(Object.keys(pair));
  expect(canonicalSidecar(b).toString('utf8')).toContain(publicMarker(b).binding_digest);
  for (const bad of [
    { ...pair, extra: 'c'.repeat(64) },
    Object.fromEntries(Object.entries(pair).slice(1)),
    { ...pair, [Object.keys(pair)[0]]: 'd'.repeat(64) },
  ])
    expect(() => orderedPair(bad, b)).toThrow();
  for (const s of ['{"schema":1,"schema":2}', '{"nested":{"x":1,"\\u0078":2}}', '{"x":1e999}'])
    expect(() => parseNativeFrame(s)).toThrow();
  expect(parseNativeFrame('{"x":"汉字"}')).toEqual({ x: '汉字' });
});
it('installed publisher/old-consumer proof is unavailable and arbitrary pins or self-created channels cannot enable a production root', () => {
  vi.stubEnv(restrictedPublicationLaunchEnvironment, '1');
  expect(supportedPublicationRoot).toBeUndefined();
  for (const spec of [
    {},
    { root: '/tmp', artifactRoot: '/tmp', sourceIdentity: 'a'.repeat(64), files: {} },
    { nativeActionId: 'fake', PUBLIC_RELEASE: true, fd: 3 },
  ])
    expect(() =>
      controlledPublicationRuntime(spec as any, { effectCurrent: () => {}, readCurrent: () => {} }),
    ).toThrow();
});

it('launch configuration is opt-in metadata and rejects ambiguous overrides', () => {
  const deferred = readRestrictedPublicationLaunchPolicy({});
  expect(deferred).toEqual({
    schema: 'restricted-publication-launch/v1', enabled: false,
    state: 'DEFERRED_POST_LAUNCH',
    deferredGates: ['ci-producer', 'coverage', 'owner-registry', 'kb', 'os-owner-census'],
  });
  for (const value of ['', '0', 'false'])
    expect(readRestrictedPublicationLaunchPolicy({ [restrictedPublicationLaunchEnvironment]: value })).toEqual(deferred);
  for (const value of ['1', 'true'])
    expect(readRestrictedPublicationLaunchPolicy({ [restrictedPublicationLaunchEnvironment]: value })).toEqual({
      schema: deferred.schema, enabled: true, state: 'ENABLED', deferredGates: [],
    });
  for (const value of ['TRUE', ' true ', 'yes', 'enabled'])
    expect(() => readRestrictedPublicationLaunchPolicy({ [restrictedPublicationLaunchEnvironment]: value })).toThrow('RESTRICTED_PUBLICATION_CONFIGURATION_INVALID');
});

it('launch default defers the real assembly and runtime before coverage or owner census construction', () => {
  vi.stubEnv(restrictedPublicationLaunchEnvironment, undefined);
  expect(() => createControlledPublicationAssembly(undefined as any, 'plugin', undefined as any)).toThrow('RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH');
  const current = vi.fn();
  expect(resolveControlledPublicationRoot(undefined, null, current)).toBeUndefined();
  expect(current).toHaveBeenCalledOnce();
  expect(() => resolveControlledPublicationRoot(undefined, null, () => { throw Error('OWNER_CHANGED'); })).toThrow('OWNER_CHANGED');
  expect(() => controlledPublicationRuntime(undefined as any, {
    effectCurrent: current, readCurrent: current,
  })).toThrow('RESTRICTED_PUBLICATION_DEFERRED_POST_LAUNCH');
  expect(supportedPublicationRoot).toBeUndefined();
});
