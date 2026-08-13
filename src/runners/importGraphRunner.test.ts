import { describe, expect, it } from 'vitest';
import { extractImports } from './importGraphRunner';

describe('extractImports', () => {
  it('extracts static, dynamic, and require imports', () => {
    const source = [
      "import a from 'pkg-a';",
      "export { b } from 'pkg-b';",
      "const c = require('pkg-c');",
      "const d = await import('pkg-d');",
    ].join('\n');
    expect(extractImports(source)).toEqual(['pkg-a', 'pkg-b', 'pkg-c', 'pkg-d']);
  });

  it('ignores imports inside line and block comments', () => {
    const source = [
      "// import commented from 'commented-line';",
      "/* const x = require('commented-block'); */",
      "/**",
      " * import doc from 'commented-doc';",
      " */",
      "import real from 'real-pkg';",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-pkg']);
  });

  it('ignores type-only imports and exports', () => {
    const source = [
      "import type { T } from 'types-only';",
      "export type { U } from 'types-only-export';",
      "import real from 'real-pkg';",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-pkg']);
  });

  it('still extracts value imports that include inline type specifiers', () => {
    const source = "import { type T, realThing } from 'mixed-pkg';";
    expect(extractImports(source)).toEqual(['mixed-pkg']);
  });
});
