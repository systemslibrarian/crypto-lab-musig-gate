/* What "audited" covers for the @noble/curves this lab ships.
 *
 * The README and src/musig/field.ts both introduced it as "@noble/curves —
 * audited, and ... NOT the teaching subject", with no version. The library
 * records its latest independent audit as "at version 2.3.0, in Aug 2026, by
 * [Trail of Bits]", scope "everything"; this lab pins ^2.4.0, one release past.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const flat = (text: string) => text.replace(/\n\s*\*\s?/g, ' ').replace(/\s+/g, ' ');

const pkg = JSON.parse(read('../../package.json'));
const nobleReadme = read('../../node_modules/@noble/curves/README.md');

describe('the @noble/curves audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
  });

  it('names that version wherever the library is introduced', () => {
    for (const [name, text] of [
      ['README.md', flat(read('../../README.md'))],
      ['src/musig/field.ts', flat(read('./field.ts'))],
    ] as const) {
      expect(text, name).not.toContain('@noble/curves — audited, and');
      expect(text, name).not.toContain('** — audited, and deliberately');
      expect(text, name).toContain('at version 2.3.0, in Aug 2026, by [Trail of Bits]');
      expect(text, name).toMatch(/\^2\.4\.0/);
    }
  });
});
