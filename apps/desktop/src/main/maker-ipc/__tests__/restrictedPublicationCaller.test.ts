import { expect, it } from 'vitest';
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
  supportedPublicationRoot,
} from '../restrictedPublicationCaller.js';
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
