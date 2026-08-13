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

  it('does not let a type-only import suppress the next statement', () => {
    const source = [
      "import type { T } from 'types-only';",
      "import real from 'real-pkg';",
    ].join(' ');
    expect(extractImports(source)).toEqual(['real-pkg']);
  });

  it('is not confused by comment markers inside regex literals', () => {
    const source = [
      "const re1 = /https:\\/\\//;",
      "const re2 = /[/*]/;",
      "const re3 = /it's got an apostrophe/;",
      "const re4 = x / y; // real comment with require('commented')",
      "import real from 'real-pkg';",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-pkg']);
  });

  it('fails open on unterminated block comments instead of blanking the file', () => {
    const source = [
      "import real from 'real-pkg';",
      "const x = 1; /* unterminated block comment",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-pkg']);
  });
});
