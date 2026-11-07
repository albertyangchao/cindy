/** tier: unit. Compile the real fixed Python bootstraps; never import/publish any runtime root. */
import { execFileSync } from 'node:child_process';
import { expect, it } from 'vitest';
import {
  publicationPython,
  publicationManagedEntryPython,
} from '../restrictedPublicationPython.js';
it('the actual stage and generic managed entry bootstraps compile with the real supported Python interpreter', () => {
  const out = execFileSync(
    'python3.11',
    [
      '-I',
      '-c',
      'import ast,json,sys; values=json.load(sys.stdin);[ast.parse(v) for v in values];print(len(values))',
    ],
    { input: JSON.stringify([publicationPython, publicationManagedEntryPython]), encoding: 'utf8' },
  );
  expect(out.trim()).toBe('2');
});
