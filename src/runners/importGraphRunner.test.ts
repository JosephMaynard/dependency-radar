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

  it('ignores import-looking text inside ordinary strings and templates', () => {
    const source = [
      'const doc = "require(\'ghost-pkg\')";',
      "const esm = 'import x from \"ghost-esm\"';",
      'const tpl = `import("ghost-dynamic")`;',
      "import real from 'real-pkg';",
      "const lazy = require('lazy-pkg');",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-pkg', 'lazy-pkg']);
  });

  it('masks regex literal bodies so import-shaped regex text never counts', () => {
    const source = [
      "const re = /import fake from 'ghost-pkg'/;",
      "function f() { return /require\\('ghost-return'\\)/; }",
      "import real from 'real-pkg';",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-pkg']);
  });

  it('ignores TypeScript import() type queries but keeps dynamic imports', () => {
    const source = [
      "type Package = import('types-only').Package;",
      "export type Other = import('types-only-export').Other;",
      "const mod = await import('real-dynamic');",
    ].join('\n');
    expect(extractImports(source)).toEqual(['real-dynamic']);
  });

  it('keeps slash-after-closer contexts as division while block-context regexes stay masked', () => {
    const source = [
      "const a = arr[0] / 2; const m1 = require('pkg-bracket');",
      "const b = getW() / 2; const m2 = require('pkg-paren');",
      "if (cond) {} /import fake from 'ghost'/ .test(s); const m3 = require('pkg-block');",
    ].join('\n');
    expect(extractImports(source)).toEqual(['pkg-bracket', 'pkg-paren', 'pkg-block']);
  });
});
